/// Recopying from the same user buffer frequently indicates a pattern of
/// Reading a size header, allocating, and then re-reading an entire
/// structure. If the structure's size is not re-validated, this can lead
/// to structure or data size confusions.
///
// Confidence: Moderate
// Copyright: (C) 2013 Kees Cook, Chromium.  GPLv2.
// URL: http://coccinelle.lip6.fr/
// Comments:
// Options: --no-includes --include-headers

virtual report
virtual org
virtual context

@ok@
position p;
expression src,dest;
@@

copy_from_user@p(&dest, src, sizeof(dest))

@cfu_twice@
position p != ok.p;
identifier src;
expression dest1, dest2, size1, size2, offset, e1, e2;
@@

*copy_from_user(dest1, src, size1)
 ... when != src = offset
     when != src += offset
     when != src -= offset
     when != src ++
     when != src --
     when != if (size2 > e1 || ...) { ... return ...; }
     when != if (size2 > e1 || ...) { ... size2 = e2 ... }
*copy_from_user@p(dest2, src, size2)

@script:python depends on org@
p << cfu_twice.p;
@@

cocci.print_main("potentially dangerous second copy_from_user()",p)

@script:python depends on report@
p << cfu_twice.p;
@@

coccilib.report.print_report(p[0],"potentially dangerous second copy_from_user()")
