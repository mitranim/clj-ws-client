(ns app.util
  (:require
    [clojure.core.match :refer [match]]
    [clojure.core.async.impl.protocols :as protocols]
    [clojure.core.async.impl.dispatch :as dispatch]))

(set! *warn-on-reflection* true)

(defn reduced-when-err [value]
  (if (err? value) (reduced value) value))

(defmacro unreduce-or [sym expr] {:pre [(symbol? sym)]}
  `(if (reduced? ~sym) (unreduced ~sym) ~expr))

(defn imp-block [[expr & tail-exprs]]
  (match expr

    (('let pattern init) :seq)
    (if-not tail-exprs
      (list init)
      (match (imp-block tail-exprs)
        (((((:or 'let `let) bindings & tail) :seq)) :seq)
        `((let [~pattern ~init ~@bindings] ~@tail))
        block-tail
        `((let [~pattern ~init] ~@block-tail))))

    (('let & _) :seq)
    (throw (new IllegalArgumentException
                "in the root of an `imp` block, `let` must have the form: (let pattern init)"))

    :else
    (if-not tail-exprs
      (list expr)
      `(~expr ~@(imp-block tail-exprs)))))

(defn list-to-expr [[expr & tail-exprs]]
  (if-not tail-exprs expr `(do ~expr ~@tail-exprs)))

(defmacro imp
  "Variant of a `do` block where `let` emulates imperative-style variable
  assignment. Convenient for inserting assertions and other side-effectul
  operations between bindings.

  Usage:

    (imp
      (let pattern <expr>)
      (when-not <assertion> (throw <fail>))
      (let pattern <expr>)
      (let pattern <expr>)
      <exprs>
      ...)

  Each `let` creates a subscope. Adjacent lets are merged together.

  Examines only the let expressions at the root level that start with the
  raw 'let symbol. Ignores subforms and 'clojure.core/let."
  [& exprs]
  (list-to-expr (imp-block exprs)))

(defmacro do?
  "Variant of a `do` block with early interruption via clojure.core/reduced.
  When a subform satisfies clojure.core/reduced?, the block short-curcuits,
  immediately returning that value.

  Expansion:

    (do?
      expr  |  (let [value expr] (if (reduced? value) (unreduced value)
      expr  |    (let [value expr] (if (reduced? value) (unreduced value)
      expr  |      (let [value expr] (if (reduced? value) (unreduced value) value)))))))
  "
  [& [expr & tail-exprs]]
  (if tail-exprs
    `(let [value# ~expr]
       (unreduce-or value# (do? ~@tail-exprs)))
    `(unreduced ~expr)))

(defn imp?-expr [exprs]
  (when-let [[expr & tail-exprs] (seq exprs)]
    (match expr

      (('let pattern init) :seq)
      `(let [value# ~init]
         (unreduce-or
           value#
           (let [~pattern value#] ~(imp?-expr tail-exprs))))

      (('let & _) :seq)
      (throw (new IllegalArgumentException
                  "in the root of an `imp?` block, `let` must have the form: (let pattern init)"))

      :else
      (if
        tail-exprs
        `(let [value# ~expr]
           (unreduce-or value# ~(imp?-expr tail-exprs)))
        `(unreduced ~expr)))))

(defmacro imp?
  "Variant of a `do` block that emulates imperative assignment and supports
  early interruption via clojure.core/reduced. Conceptual combination of `imp`
  and `do?`. See `(doc imp)` for assignment, and `(doc do?)` for interruption.

  Usage:

    (imp?
      (let [one two] (range 10))
      (when (> one 10)
        (reduced :early-result))
      (let [three four] (range 20))
      :late-result)

  General form:

    (imp?
      (let pattern reduced-or-result)
      (let pattern reduced-or-result)
      reduced-or-result
      reduced-or-result
      (let pattern reduced-or-result)
      reduced-or-result
      ...)

  Expansion:

    (imp?
      (let pattern init)  |  (let [value init] (if (reduced? value) (unreduced value) (let [pattern value]
      (let pattern init)  |    (let [value init] (if (reduced? value) (unreduced value) (let [pattern value]
      expr                |      (let [value expr] (if (reduced? value) (unreduced value)
      (let pattern init)  |        (let [value init] (if (reduced? value) (unreduced value) (let [pattern value]
      expr                |          (let [value expr] (if (reduced? value) (unreduced value)
      expr                |            (let [value expr] (if (reduced? value) (unreduced value)
      (let pattern init)  |              (let [value init] (if (reduced? value) (unreduced value) (let [pattern value]
      (let pattern init)  |                (let [value init] (if (reduced? value) (unreduced value) (let [pattern value]
      expr                |                  (let [value expr] (if (reduced? value) (unreduced value)
      expr                |                    (let [value expr] (if (reduced? value) (unreduced value) value)))))))))))))))))))))))))
  "
  [& exprs]
  (imp?-expr exprs))

(defn async-handler-commit-fn [handler]
  (locking handler
    (when (protocols/active? handler)
      (protocols/commit handler))))

(defn fn-take [handler take-fn]
  ; No buffering, handlers must be willing to wait.
  (if-not (protocols/blockable? handler)
    nil-d
    (if-let [commit (async-handler-commit-fn handler)]
      (do
        (dispatch/run (fn fn-take-async [] (commit (take-fn))))
        nil)
      nil-d)))

(defn fn-put [value handler closed? put-fn]
  ; Racy, but sending doesn't guarantee delivery anyway.
  (if closed?
    false-d
    (do
      (dispatch/run (fn fn-put-async [] (put-fn value)))
      true-d)))
