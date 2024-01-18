// SPDX-License-Identifier: GPL-2.0-only
///
/// Replace intentional wrap-around addition with calls to
/// check_add_overflow() and add_would_overflow(), see
/// Documentation/process/deprecated.rst
///
//
// Confidence: High
// Comments:
// Options: --no-includes --include-headers

virtual context
virtual report
virtual org
virtual patch

@report_wrap_sum depends on !patch@
type RESULT;
RESULT VAR;
expression OFFSET;
@@

 {
        RESULT sum;
        ...
        (
*       VAR + OFFSET < VAR
        )
        ...
        (
        VAR + OFFSET
        )
        ...
 }

@wrap_sum depends on patch@
type RESULT;
RESULT VAR;
expression OFFSET;
@@

 {
+       RESULT sum;
        ...
        (
-       VAR + OFFSET < VAR
+       check_add_overflow(VAR, OFFSET, &sum)
        )
        ...
        (
-       VAR + OFFSET
+       sum
        )
        ...
 }

@report_wrap depends on !patch && !report_wrap_sum@
identifier PTR;
expression OFFSET;
@@

*       PTR + OFFSET < PTR

@patch_wrap depends on patch && !wrap_sum@
identifier PTR;
expression OFFSET;
@@

-       PTR + OFFSET < PTR
+       add_would_overflow(PTR, OFFSET)
