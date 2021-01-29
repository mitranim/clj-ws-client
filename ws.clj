(ns app.ws
  "Less terrible WebSocket client for Clojure.

  Written in pure Clojure with no dependencies other than JVM built-ins.
  Relatively low level, keeps you in control while handling the grittier parts
  of the protocol.

  Pros:

    * no dependencies
    * no callbacks: you control the execution
    * reconnecting is as simple as writing a loop

  Cons:

    * new and immature

  +/-:

    * uses blocking IO

  See spec: https://tools.ietf.org/html/rfc6455
  "
  (:require
    [clojure.pprint :refer [pprint] :rename {pprint pp}]
    [clojure.core.async.impl.protocols :as protocols]
    [clojure.string :as string]
    [app.util :as util :refer [imp imp? base64-encode sha-1]])
  (:import
    [java.io DataInput DataInputStream DataOutput DataOutputStream
     ByteArrayOutputStream EOFException]
    [java.net URI Socket ProtocolException SocketException ConnectException]
    [javax.net.ssl SSLContext SSLSocketFactory]
    [java.nio ByteBuffer]
    [java.nio.charset Charset StandardCharsets]))

(set! *warn-on-reflection* true)



(def DEFAULT_WS_PORT 80)
(def DEFAULT_WSS_PORT 443)

(def ^Byte OPCODE_CONTINUE (byte 0))
(def ^Byte OPCODE_TEXT     (byte 1))
(def ^Byte OPCODE_BINARY   (byte 2))
(def ^Byte OPCODE_CLOSE    (byte 8))
(def ^Byte OPCODE_PING     (byte 9))
(def ^Byte OPCODE_PONG     (byte 10))

(def OPCODES
  {:CONTINUE OPCODE_CONTINUE
   :TEXT     OPCODE_TEXT
   :BINARY   OPCODE_BINARY
   :CLOSE    OPCODE_CLOSE
   :PING     OPCODE_PING
   :PONG     OPCODE_PONG})

(def OPCODE_NAMES (clojure.set/map-invert OPCODES))

(def OPCODE_SET (set (vals OPCODES)))

(def CONTROL_OPCODE_SET #{OPCODE_CONTINUE OPCODE_CLOSE OPCODE_PING OPCODE_PONG})

(def STATUS_CODES
  {:NORMAL_CLOSURE          1000
   :ENDPOINT_GOING_AWAY     1001
   :PROTOCOL_ERROR          1002
   :UNRECOGNIZED_DATA       1003
   :UNEXPECTED_MESSAGE_TYPE 1007
   :POLICY_VIOLATION        1008
   :MESSAGE_TOO_BIG         1009
   :MISSING_EXTENSIONS      1010
   :UNEXPECTED_ERROR        1011})

(def STATUS_CODE_NAMES (clojure.set/map-invert STATUS_CODES))

(def ^:dynamic *verbose* false)
(def ^:dynamic *log-out* *out*)

(defn debug [& args]
  (when *verbose*
    (binding [*out* *log-out*]
      (print "[" (ns-name *ns*) "]")
      (when args
        (. *out* (append \space))
        (loop [[head & tail] args]
         (if (or (string? head) (char? head)) (print head) (pr head))
         (when tail
           (. *out* (append \space))
           (recur tail))))
      (newline)
      (flush))))

(defmacro debugging
  "Run exprs in an implicit do, with debug logging enabled."
  [& exprs]
  `(binding [*verbose* true] ~@exprs))

(defn to-str
  "Converts UTF8-encoded bytes to a string."
  ^String [value]
  (cond (string? value) value
        (bytes? value) (new String ^bytes value StandardCharsets/UTF_8)
        :else nil))

(defn to-str-from
  "Converts UTF8-encoded bytes to a string, starting at the given offset."
  [^bytes bytes offset]
  (when bytes
    (let [buf (ByteBuffer/wrap bytes offset (- (alength bytes) offset))
          charbuf (.decode StandardCharsets/UTF_8 buf)]
      (.toString charbuf))))

(defn to-bytes
  "Converts a string to UTF8-encoded bytes."
  ^bytes [value]
  (cond (bytes? value) value
        (string? value) (.getBytes ^String value StandardCharsets/UTF_8)
        :else nil))

(defn xor-bytes-by
  "Xors the given payload bytes with the mask bytes, byte-for-byte, cycling the
  mask. Used to encode client frames."
  ^bytes [^bytes body ^bytes mask]
  (if (or (not mask) (not body))
    body
    (let [length (alength body)
          output (byte-array length)]
      (loop [index (int 0)]
        (if-not (< index length)
          output
          (do
            (aset-byte output index (bit-xor (aget body index) (aget mask (mod index (alength mask)))))
            (recur (inc index))))))))

(def ^java.security.SecureRandom rnd (new java.security.SecureRandom))

(defn random-bytes
  "Generates an N-sized array of random bytes, using java.security.SecureRandom."
  ^bytes [len]
  (let [bytes (byte-array len)]
    (.nextBytes rnd bytes)
    bytes))

(defn random-mask
  "Generates a random byte array to serve as a frame mask."
  ^bytes []
  (random-bytes 4))

(defn random-nonce
  "Generates a random client nonce for the sec-websocket-key header."
  ^String []
  (to-str (base64-encode (random-bytes 16))))

(defn to-uri ^URI [uri]
  (if (instance? URI uri) uri (new URI uri)))

(defn to-port ^long [^URI uri]
  (cond
    (> (.getPort uri) 0)       (.getPort uri)
    (= (.getScheme uri) "ws")  DEFAULT_WS_PORT
    (= (.getScheme uri) "wss") DEFAULT_WSS_PORT
    :else (throw (new ProtocolException
                      (str "expected scheme 'ws' or 'wss', got " (.getScheme uri))))))

(defn non-empty-path [path] (if (empty? path) "/" path))

(defn client-handshake
  "Generates a client handshake."
  ^String [uri nonce] {:pre [(string? nonce)]}
  (let [uri (to-uri uri)]
    (str
      "GET " (non-empty-path (.getPath uri)) " HTTP/1.1\r\n"
      "host: " (.getHost uri) ":" (to-port uri) "\r\n"
      "upgrade: websocket\r\n"
      "connection: upgrade\r\n"
      "sec-websocket-version: 13\r\n"
      "sec-websocket-key: " nonce "\r\n")))

; https://tools.ietf.org/html/rfc6455#section-4.2.2
(defn client-nonce-to-server-nonce
  "Converts a client nonce to the server nonce for the sec-websocket-accept header."
  ^String [client-nonce] {:pre [(string? client-nonce)]}
  (-> (str client-nonce "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
      (to-bytes)
      (sha-1)
      (base64-encode)
      (to-str)))



(deftype Frame
  [^boolean fin?
   ^boolean rsv1?
   ^boolean rsv2?
   ^boolean rsv3?
   ^byte opcode
   ^bytes mask
   ^{:doc "Frame payload is unmasked when reading and masked when writing. It's stored unmasked."}
   ^bytes payload]
  clojure.lang.IDeref
  (deref [_]
    {:fin?    fin?
     :rsv1?   rsv1?
     :rsv2?   rsv2?
     :rsv3?   rsv3?
     :opcode  opcode
     :mask    mask
     :payload payload}))

(defn client-frame
  "Shortcut to creating a non-fragmented client frame with a random mask."
  ^Frame [opcode payload]
  (new Frame true false false false opcode (random-mask) payload))

(defn data-frame
  "Creates a data frame: bytes -> binary, string -> text. Throws on other
  argument types."
  ^Frame [data]
  (cond
    (bytes? data) (client-frame OPCODE_BINARY data)
    (string? data) (client-frame OPCODE_TEXT (to-bytes data))
    :else
    (throw (new IllegalArgumentException
                (str "expected bytes or string, got: " data)))))

(defn frame-data
  "Extracts data from a data frame: binary -> byte array, text -> string.
  Always returns non-nil for data frames, even if the payload is empty.
  Returns nil for non-data frames."
  [^Frame frame]
  (cond
    (not frame) nil
    (= (.opcode frame) OPCODE_BINARY) (or (.payload frame) (byte-array 0))
    (= (.opcode frame) OPCODE_TEXT) (or (to-str (.payload frame)) "")
    :else nil))

(defn byte-pair-to-unsigned-int
  "Converts two first bytes from the given byte array into an unsigned int."
  ^Integer [[b0 b1]]
  (when (and b0 b1)
    (-> (Byte/toUnsignedInt (byte b0))
        (bit-shift-left 8)
        (bit-or (Byte/toUnsignedInt b1)))))

(defn close-frame-data
  "Attempts to parse a close frame into a map containing the status code
  and message."
  [^Frame frame]
  (imp?
    (let payload (.payload frame))
    (when-not payload (reduced nil))
    (let status-code (byte-pair-to-unsigned-int payload))
    (when-not status-code (reduced nil))
    (let status-name (STATUS_CODE_NAMES status-code))
    (let message (to-str-from payload 2))
    (if status-name
      {:code status-code
       :name status-name
       :message message}
      {:code status-code
       :message message})))

(defn coalesce-frames
  "Combines a sequence of fragment frames, using the first frame's opcode and
  extension flags, and concatenating their payloads."
  ^Frame [frames]
  (let [[^Frame head] frames
        buf (new ByteArrayOutputStream)]
    (doseq [^Frame frame frames]
      (when (.payload frame) (.write buf ^bytes (.payload frame))))
    (new Frame true (.rsv1? head) (.rsv2? head) (.rsv3? head) (.opcode head) nil (.toByteArray buf))))

(defn read-n-bytes!
  "Reads N bytes from the given reader, returning a byte array."
  ^bytes [^DataInput reader len]
  (let [bytes (byte-array len)]
    (.readFully reader bytes)
    bytes))

(defn bytes-to-int
  "Converts a byte array to an integer, treating the bytes as an unsigned
  integer in the network byte order (big endian).

  Note the size mismatch:
    * WebSocket spec allows payload up to u64 bytes
    * clojure.core/byte-array allows up to i32 bytes (2 GiB)

  If someone sends a malformed frame suggesting such a huge payload,
  we should abort anyway. An overflow exception will do for now."
  ^Integer [^bytes bytes]
  (areduce bytes index num (int 0)
    (int (+ (* num 256) (Byte/toUnsignedInt (aget bytes index))))))

(defn read-frame!
  "Attempts to read a frame from the given reader. Returns nil if data could not
  be read. Due to how WebSocket frames are defined, in the face of malformed
  data this is more likely to produce pathological frames rather than fail.

  Buffers the entire payload, up to 2^32 bytes, in memory. Throws if the payload
  size is larger. Blocks until the frame has been fully read."
  ^Frame [^DataInput reader]
  (if-not reader
    (debug "Couldn't read frame: no reader found")
    ; Without this lock, concurrent reading leads to fragmented frames
    (locking reader
      (try
        (imp
          (let b0             (.readByte reader))
          (let fin?           (not= 0 (bit-and b0 2r10000000)))
          (let rsv1?          (not= 0 (bit-and b0 2r01000000)))
          (let rsv2?          (not= 0 (bit-and b0 2r00100000)))
          (let rsv3?          (not= 0 (bit-and b0 2r00010000)))
          (let opcode         (unchecked-byte (bit-and b0 2r00001111)))
          (let b1             (.readByte reader))
          (let mask?          (not= 0 (bit-and b1 2r10000000)))
          (let payload-length (unchecked-byte (bit-and b1 2r01111111)))
          (let payload-length
            (case payload-length
              126 (bytes-to-int (read-n-bytes! reader 2))
              127 (bytes-to-int (read-n-bytes! reader 8))
              payload-length))
          (let mask (when mask? (read-n-bytes! reader 4)))
          (let payload
            (when (> payload-length 0)
              (xor-bytes-by (read-n-bytes! reader payload-length) mask)))
          (new Frame fin? rsv1? rsv2? rsv3? opcode mask payload))
        (catch EOFException _
          (debug "Couldn't read frame: EOF")
          nil)))))

(defn write-data!
  "Attempts to write a chunk of data into the given DataOutput. Accepts byte
  arrays and strings, encoding strings as UTF8. Returns true if data was
  successfully written and false otherwise."
  [^DataOutput writer data]
  (try
    (.write writer (to-bytes data))
    true
    (catch SocketException err
      (debug "Couldn't write data:\n" err)
      false)))

(defn write-frame!
  "Attempts to write a frame into the given DataOutput. Returns true if data was
  successfully written and false otherwise."
  [^DataOutput writer ^Frame frame]
  (assert (instance? DataOutput writer) "expected writer to exist")
  (assert (instance? Frame frame) "expected frame to exist")
  (when-not (.mask frame)
    (debug "Attempting to write unmasked client frame!"))
  (try
    (imp
      (let b0 (byte 0))
      (let b0 (bit-or b0 (if (.fin?  frame) 2r10000000 2r00000000)))
      (let b0 (bit-or b0 (if (.rsv1? frame) 2r01000000 2r00000000)))
      (let b0 (bit-or b0 (if (.rsv2? frame) 2r00100000 2r00000000)))
      (let b0 (bit-or b0 (if (.rsv3? frame) 2r00010000 2r00000000)))
      (let b0 (bit-or b0 (bit-and (.opcode frame) 2r00001111)))
      (.write writer b0)
      (let payload-length (count (.payload frame)))
      (let bmask (if (.mask frame) (unchecked-byte 2r10000000) (unchecked-byte 2r00000000)))

      (cond
        (= payload-length 0)
        (.write writer bmask)

        (<= payload-length 125)
        (.write writer (unchecked-byte (bit-or payload-length bmask)))

        (<= payload-length Short/MAX_VALUE)
        (do
          (.write writer (unchecked-byte (bit-or 126 bmask)))
          (.writeShort writer payload-length))

        :else
        (do
          (.write writer (unchecked-byte (bit-or 127 bmask)))
          (.writeLong writer payload-length)))

      (when (.mask frame)
        (.write writer ^bytes (.mask frame)))

      (when (.payload frame)
        (.write writer ^bytes (xor-bytes-by (.payload frame) (.mask frame))))

      true)
    (catch SocketException err
      (debug "Couldn't write frame:\n" err)
      false)))



(defn conn-map
  "Creates a map representing an idle connection. See `create-conn`."
  [uri]
  {:uri (to-uri uri)
   :socket nil
   :reader nil
   :writer nil
   :fragments nil})

(defn create-conn
  "Creates an idle connection. Usage:

    (def conn (ws/create-conn uri))
    (ws/conn-open-and-handshake! conn)
    (ws/conn-read-data! conn)
    (ws/conn-write-data! conn bytes-or-string)
  "
  [uri]
  (atom (conn-map uri)))

(defn conn-closed?
  "True if the connection has been closed. Beware of race conditions: the
  connection state may change immediately after the call."
  [conn]
  (let [^Socket socket (:socket @conn)]
    (or (not (instance? Socket socket)) (.isClosed socket))))

; Technically we're supposed to wait for a close frame in response...
(defn conn-close!
  "Idempotently closes the connection, sending a close frame if possible."
  [conn]
  (locking conn
    (let [{:keys [uri ^Socket socket ^DataOutput writer]} @conn]
      (when writer
        (try (write-frame! writer (client-frame OPCODE_CLOSE nil))
          (catch SocketException _)
          (catch EOFException _)))
      (when socket (.close socket))
      (swap! conn merge (conn-map uri))))
  nil)

(defn conn-abrupt-close!
  "Idempotently closes the connection without sending a close frame."
  [conn]
  (locking conn
    (let [{:keys [uri ^Socket socket]} @conn]
      (when socket (.close socket))
      (swap! conn merge (conn-map uri))))
  nil)

(def ^SSLSocketFactory ssl-socket-factory
  (.getSocketFactory (SSLContext/getDefault)))

(defn to-ssl-socket
  "Wraps into an SSL-enabled socket."
  ^Socket [^Socket socket ^URI uri]
  (.createSocket ssl-socket-factory socket (.getHost uri) (to-port uri) true))

(defn conn-open-socket!
  "Opens or reopens the connection, closing the previous socket, if any. Blocks
  until the new socket is connected and the previous one is closed.
  To open with a handshake, use `conn-handshake!`, `conn-open-and-handshake!`."
  [conn]
  (locking conn
    (let [^URI uri (:uri @conn)
          ; Connect synchronously
          socket (new Socket (.getHost uri) (to-port uri))
          socket (if (= (.getScheme uri) "wss") (to-ssl-socket socket uri) socket)]
      ; At this point the new socket is connected, let's drop the old one
      (conn-close! conn)
      (swap! conn assoc
        :socket socket
        :reader (new DataInputStream  (.getInputStream socket))
        :writer (new DataOutputStream (.getOutputStream socket))
        :fragments [])))
  nil)

; Should we group repeating headers into lists?
(defn read-headers!
  "Reads lines from a reader until a blank line, parsing them into a map.
  Converts header names to lower case."
  [^DataInput line-reader]
  (let [header-map (transient {})]
    (loop []
      (let [line (.readLine line-reader)]
        (if (string/blank? line)
          (persistent! header-map)
          (let [[key val] (string/split line #":" 2)]
            (when-not (string/blank? key)
              (assoc!
                header-map
                (string/lower-case (string/trim key))
                (when val (string/trim val))))
            (recur)))))))

(defn str≈
  "Case-insensitive string equality."
  [one other]
  (and (string? one)
       (string? other)
       (.equalsIgnoreCase ^String one other)))

(defn conn-send-handshake!
  "Formulates and sends a client handshake. See `client-handshake`."
  [conn]
  (locking conn
    (let [{:keys [uri writer]} @conn
          nonce (random-nonce)
          handshake (client-handshake uri nonce)]
      (debug "Sending client handshake...")
      (write-data! writer handshake)
      (write-data! writer "\r\n")
      {:nonce nonce})))

(defn conn-receive-handshake!
  "Reads and validates a server handshake, attempting to conform to the
  specification. Must be called after sending the client handshake. If
  validation fails, closes the connection and throws a
  java.net.ProtocolException. Returns the server headers as a map."
  [conn client-nonce]
  (locking conn
    (try
      (imp
        (loop [leeway (int 3)]
          (let [start-line (.readLine ^DataInput (:reader @conn))]
            (if (string/blank? start-line)
              (if (> leeway 0)
                (recur (dec leeway))
                (throw (new ProtocolException
                            "malformed server handshake: multiple empty lines")))
              (when (not= start-line "HTTP/1.1 101 Switching Protocols")
                (throw (new ProtocolException
                            (str "unexpected status line in server handshake: " start-line)))))))

        (let headers (read-headers! (:reader @conn)))
        (when-not (str≈ (headers "connection") "upgrade")
          (throw (new ProtocolException
                      (str "missing or malformed connection header: " (headers "connection")))))
        (when-not (str≈ (headers "upgrade") "websocket")
          (throw (new ProtocolException
                      (str "missing or malformed upgrade header: " (headers "upgrade")))))

        (let server-nonce (headers "sec-websocket-accept"))
        (when-not server-nonce
          (throw (new ProtocolException "missing sec-websocket-accept nonce")))

        (let expected-nonce (client-nonce-to-server-nonce client-nonce))
        (when (not= server-nonce expected-nonce)
          (throw (new ProtocolException "mismatch in sec-websocket-accept nonce")))

        ; TODO this must be based on client handshake
        (when-not (empty? (headers "sec-websocket-extensions"))
          (throw (new ProtocolException
                      (str "server suggested unsupported extensions: " (headers "sec-websocket-extensions")))))

        (debug "Received and validated server handshake:\n" headers)

        headers)

      (catch ProtocolException err
        (conn-close! conn)
        (throw err)))))

(defn conn-handshake!
  "Attempts a full handshake cycle, sending a client handshake and validating
  the server handshake. See `conn-receive-handshake!` for validation. Returns
  the server headers as a map."
  [conn]
  (locking conn
    (let [{nonce :nonce} (conn-send-handshake! conn)]
      (conn-receive-handshake! conn nonce))))

(defn conn-open-and-handshake!
  "Attempts to reopen the connection and run the full handshake cycle. If
  successful, the connection is ready to send and receive frames."
  [conn]
  (locking conn
    (conn-open-socket! conn)
    (conn-handshake! conn)))

(defn conn-write-frame! [conn frame]
  (write-frame! (:writer @conn) frame))

(defn conn-write-data! [conn data]
  (conn-write-frame! conn (data-frame data)))

(defn non-empty-conj [coll val]
  (when-not (empty? coll) (conj coll val)))

(defn first-fragment? [^Frame frame]
  (and (not (.fin? frame)) (not= (.opcode frame) OPCODE_CONTINUE)))

(defn middle-fragment? [^Frame frame]
  (and (not (.fin? frame)) (= (.opcode frame) OPCODE_CONTINUE)))

(defn final-fragment? [^Frame frame]
  (and (.fin? frame) (= (.opcode frame) OPCODE_CONTINUE)))

(defn conn-read-frame!
  "Attempts to receive a complete frame over the connection. Implements the
  spec-mandated client behavior:

    * buffer and combine fragment frames
    * respond to ping with pong
    * close on close frame
    * close on unrecognized opcode
    * close on unexpected extension (currently doesn't expect any extensions)
    * close on masked frame
    * close on fragmented control frame

  Returns the received frame. To ignore non-data frames, use `(frame-data frame)`.
  Returns nil if the connection is closed or unavailable at any point.

  Buffers fragmented frames in memory, which may be hazardous in case of large
  fragmented payloads intended for streaming."
  ^Frame [conn]
  (locking conn
    (if-let [^Frame frame
             (try (read-frame! (:reader @conn))
               (catch SocketException err
                 (debug "Couldn't read frame: SocketException\n" err)))]
      (cond
        (not (contains? OPCODE_SET (.opcode frame)))
        (do
          (debug
            (str "Received frame with unrecognized opcode " (.opcode frame) ", closing connection\n")
            frame)
          (conn-close! conn)
          frame)

        ; TODO this must be based on handshake
        (or (.rsv1? frame) (.rsv2? frame) (.rsv3? frame))
        (do
          (debug "Received frame with unsupported extensions, closing connection\n" frame)
          (conn-close! conn)
          frame)

        (.mask frame)
        (do
          (debug "Received unexpected masked frame, closing connection\n" frame)
          (conn-close! conn)
          frame)

        (and (contains? CONTROL_OPCODE_SET (.opcode frame)) (not (.fin? frame)))
        (do
          (debug "Received fragmented control frame, closing connection\n" frame)
          (conn-close! conn)
          frame)

        (= (.opcode frame) OPCODE_CLOSE)
        (do
          (debug
            "Received close frame, closing connection\n"
            "Close frame data:\n"
            (close-frame-data frame))
          (conn-close! conn)
          frame)

        (= (.opcode frame) OPCODE_PING)
        (do
          (debug "Received ping frame, responding with pong")
          (conn-write-frame! conn (client-frame OPCODE_PONG nil))
          frame)

        (first-fragment? frame)
        (do
          (debug "Received initial frame fragment, buffering")
          (swap! conn assoc :fragments [frame])
          (conn-read-frame! conn))

        (middle-fragment? frame)
        (do
          (debug "Received middle frame fragment, buffering")
          (swap! conn update :fragments non-empty-conj frame)
          (conn-read-frame! conn))

        (final-fragment? frame)
        (let [[{frags :fragments}] (swap-vals! conn assoc :fragments nil)]
          (if (empty? frags)
            (do
              (debug "Received final frame fragment but no other fragments were found, ignoring")
              (conn-read-frame! conn))
            (do
              (debug "Received final frame fragment, coalescing")
              (coalesce-frames (conj frags frame)))))

        :else frame)
      (do
        (debug "Couldn't read frame, closing connection")
        (conn-close! conn)
        nil))))

(defn conn-read-data!
  "Attempts to receive a data frame over the connection, returning the unpacked
  payload. Ignores non-data frames; see `conn-read-frame!` for the receiving
  logic. Returns nil if the connection is closed at any point."
  [conn]
  (loop []
    (if-let [frame (conn-read-frame! conn)]
      (or (do
            ; (debug "Extracting data from frame:\n" frame)
            (frame-data frame))
          (do
            (debug "Skipping non-data or empty frame:\n" frame)
            (recur)))
      (debug "Couldn't receive frame"))))

(defn conn-frame-chan [conn]
  (let [take! (fn take! [] (conn-read-frame! conn))
        put! (fn put! [value] (conn-write-frame! conn value))]
    (reify
      protocols/Channel
      (closed? [_] (conn-closed? conn))
      (close! [_] (conn-close! conn))
      protocols/ReadPort
      (take! [_ handler] (util/fn-take handler take!))
      protocols/WritePort
      (put! [_ value handler] (util/fn-put value handler (conn-closed? conn) put!)))))

(defn conn-data-chan [conn]
  (let [take! (fn take! [] (conn-read-data! conn))
        put! (fn put! [value] (conn-write-data! conn value))]
    (reify
      protocols/Channel
      (closed? [_] (conn-closed? conn))
      (close! [_] (conn-close! conn))
      protocols/ReadPort
      (take! [_ handler] (util/fn-take handler take!))
      protocols/WritePort
      (put! [_ value handler] (util/fn-put value handler (conn-closed? conn) put!)))))
