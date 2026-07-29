; SPDX-License-Identifier: MPL-2.0
;; guix.scm — GNU Guix package definition for plasma-parser-writer
;; Usage: guix shell -f guix.scm

(use-modules (guix packages)
             (guix build-system gnu)
             (guix licenses))

(package
  (name "plasma-parser-writer")
  (version "0.1.0")
  (source #f)
  (build-system gnu-build-system)
  (synopsis "plasma-parser-writer")
  (description "plasma-parser-writer — part of the hyperpolymath ecosystem.")
  (home-page "https://github.com/hyperpolymath/plasma-parser-writer")
  (license mpl2.0))
