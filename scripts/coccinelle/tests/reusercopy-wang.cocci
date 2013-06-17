/// Recopying from the same user buffer frequently indicates a pattern of
/// reading a size header, allocating, and then re-reading an entire
/// structure. If the structure's size is not re-validated, this can lead
/// to structure or data size confusions.
///
// Confidence: Moderate
// Copyright: (C) 2013 Kees Cook, Chromium.
// Copyright: (C) 2016 Pengfei Wang.
// License: GPLv2.
// URL: http://coccinelle.lip6.fr/
// Comments:
// Options: --no-includes --include-headers

virtual report
virtual org
virtual context

@initialize:python@
@@
# -------------------------Post Matching Process--------------------------
def post_match_process(rule,p1,p2,src,ptr):
	filename = p1[0].file
	first = int(p1[0].line)
	second = int(p2[0].line)

	src_str = str(src)
	ptr_str = str(ptr)

	# Remove loop case, first and second fetch are not supposed to be
	# in the same line.
	if first == second: 
		return

	# Remove reverse loop case, where first fetch behind second fetch
	# but in last loop .
	if first > second:
		return

	# Remove false matching of src ===> (int*)src , but leave
	# function call like u64_to_uptr(ctl_sccb.sccb)
	if src_str.find("(") == 0 or ptr_str.find("(") == 0:
		return

	coccilib.report.print_report(p2[0],
		"potentially dangerous second copy_from_user() (rule %d: line %d vs line %d)" %
			(rule, first, second))
	

//-----------------Pattern Matching Rules-----------------------------------
//------------------------------- case 1: normal case without src assignment
@ rule1 disable drop_cast exists @
expression addr,exp1,exp2,src,size1,size2,offset,e1,e2;
position p1,p2;
identifier func;
type T1,T2;
@@
	func(...){
	...	
(
	copy_from_user(exp1, (T1)src, size1)@p1
|
	copy_from_user(exp1, src, size1)@p1
|
	__copy_from_user(exp1, (T1)src, size1)@p1
|
	__copy_from_user(exp1, src, size1)@p1

)
	...	when any
		when != src = addr
		when != src ++
		when != src --
		when != src += offset	
		when != src -= offset
		when != src = src + offset
		when != src = src - offset
		when != if (size2 > e1 || ...) { ... return ...; }
		when != if (size2 > e1 || ...) { ... size2 = e2 ... }
		
(
	__copy_from_user(exp2,(T2)src,size2)@p2
|
	__copy_from_user(exp2, src,size2)@p2
|
	copy_from_user(exp2,(T2)src,size2)@p2
|
	copy_from_user(exp2, src,size2)@p2
)	
	...
	}

@script:python depends on report@
p11 << rule1.p1;
p12 << rule1.p2;
s1 << rule1.src;
@@

if p11 and p12:
	post_match_process(1, p11, p12, s1, s1)

//------------------------------ case 2: ptr = src at beginning, ptr first
@ rule2 disable drop_cast exists @
identifier func;
expression addr,exp1,exp2,src,ptr,size1,size2,offset,e1,e2;
position p0,p1,p2;
type T0,T1,T2;
@@


	func(...){
	...	
(
	ptr = (T0)src@p0 // potential assignment case
|
	ptr = src@p0
)
	... 
(
	copy_from_user(exp1, (T1)ptr,size1)@p1
|
	copy_from_user(exp1, ptr,size1)@p1
|
	__copy_from_user(exp1, (T1)ptr,size1)@p1
|
	__copy_from_user(exp1, ptr,size1)@p1
)
	...	
		when != src = addr
		when != src ++
		when != src --
		when != src += offset	
		when != src -= offset
		when != src = src + offset
		when != src = src - offset
		when != if (size2 > e1 || ...) { ... return ...; }
		when != if (size2 > e1 || ...) { ... size2 = e2 ... }
(
	__copy_from_user(exp2,(T2)src,size2)@p2
|
	__copy_from_user(exp2, src,size2)@p2
|
	copy_from_user(exp2,(T2)src,size2)@p2
|
	copy_from_user(exp2, src,size2)@p2
)
	... 
	}

@script:python depends on report@
p21 << rule2.p1;
p22 << rule2.p2;
p2 << rule2.ptr;
s2 << rule2.src;
@@
if p21 and p22:
	post_match_process(2, p21, p22, s2, p2)
//------------------------- case 3: ptr = src at beginning, src first
@ rule3 disable drop_cast exists @
identifier func;
expression addr,exp1,exp2,src,ptr,size1,size2,offset,e1,e2;
position p0,p1,p2;
type T0,T1,T2;
@@


	func(...){
	...	
(
	ptr = (T0)src@p0 // potential assignment case
|
	ptr = src@p0
)
	... 
(
	copy_from_user(exp1, (T1)src,size1)@p1
|
	copy_from_user(exp1, src,size1)@p1
|
	__copy_from_user(exp1, (T1)src,size1)@p1
|
	__copy_from_user(exp1, src,size1)@p1
)
	...	
		when != src = addr
		when != src ++
		when != src --
		when != src += offset	
		when != src -= offset
		when != src = src + offset
		when != src = src - offset
		when != if (size2 > e1 || ...) { ... return ...; }
		when != if (size2 > e1 || ...) { ... size2 = e2 ... }
(
	__copy_from_user(exp2,(T2)ptr,size2)@p2
|
	__copy_from_user(exp2, ptr,size2)@p2
|
	copy_from_user(exp2,(T2)ptr,size2)@p2
|
	copy_from_user(exp2, ptr,size2)@p2
)
	... 
	}

@script:python depends on report@
p31 << rule3.p1;
p32 << rule3.p2;
p3 << rule3.ptr;
s3 << rule3.src;
@@
if p31 and p32:
	post_match_process(3, p31, p32, s3, p3)
//----------------------------------- case 4: ptr = src at middle

@ rule4 disable drop_cast exists @
identifier func;
expression addr,exp1,exp2,src,ptr,size1,size2,offset,e1,e2;
position p0,p1,p2;
type T0,T1,T2;
@@


	func(...){
	...	
(
	copy_from_user(exp1, (T1)src,size1)@p1
|
	copy_from_user(exp1, src,size1)@p1
|
	__copy_from_user(exp1, (T1)src,size1)@p1
|
	__copy_from_user(exp1, src,size1)@p1
)
	...	
		when != src = addr
		when != src ++
		when != src --
		when != src += offset	
		when != src -= offset
		when != src = src + offset
		when != src = src - offset
		when != if (size2 > e1 || ...) { ... return ...; }
		when != if (size2 > e1 || ...) { ... size2 = e2 ... }

(
	ptr = (T0)src@p0 // potential assignment case
|
	ptr = src@p0
)
	... 
		when != ptr = addr
		when != ptr ++
		when != ptr --
		when != ptr += offset	
		when != ptr -= offset
		when != ptr = ptr + offset
		when != ptr = ptr - offset
		when != if (size2 > e1 || ...) { ... return ...; }
		when != if (size2 > e1 || ...) { ... size2 = e2 ... }

(
	__copy_from_user(exp2,(T2)ptr,size2)@p2
|
	__copy_from_user(exp2, ptr,size2)@p2
|
	copy_from_user(exp2,(T2)ptr,size2)@p2
|
	copy_from_user(exp2, ptr,size2)@p2
)
	... 
	}

@script:python depends on report@
p41 << rule4.p1;
p42 << rule4.p2;
p4 << rule4.ptr;
s4 << rule4.src;
@@
if p41 and p42:
	post_match_process(4, p41, p42, s4, p4)

//-------------------- case 5: first element, then ptr, copy from structure
@ rule5 disable drop_cast exists @
identifier func, f1;
expression addr,exp1,exp2,src,size1,size2,offset,e1,e2;
position p1,p2;
type T1,T2;
@@


	func(...){
	...	
(
	copy_from_user(exp1, (T1)src->f1,size1)@p1
|
	copy_from_user(exp1, src->f1,size1)@p1
|
	copy_from_user(exp1, &(src->f1),size1)@p1
|
	__copy_from_user(exp1, (T1)src->f1,size1)@p1
|
	__copy_from_user(exp1, src->f1,size1)@p1
|
	__copy_from_user(exp1, &(src->f1),size1)@p1
)
	...	
		when != src = addr
		when != src ++
		when != src --
		when != src += offset	
		when != src -= offset
		when != src = src + offset
		when != src = src - offset
		when != if (size2 > e1 || ...) { ... return ...; }
		when != if (size2 > e1 || ...) { ... size2 = e2 ... }
(
	__copy_from_user(exp2,(T2)src,size2)@p2
|
	__copy_from_user(exp2,src,size2)@p2
|
	copy_from_user(exp2,(T2)src,size2)@p2
|
	copy_from_user(exp2,src,size2)@p2
)
	... 
	}

@script:python depends on report@
p51 << rule5.p1;
p52 << rule5.p2;
s5 << rule5.src;
e5 << rule5.f1;
@@
if p51 and p52:
	post_match_process(5, p51, p52, s5, e5)


//---------------------- case 6: first element, then ptr, copy from pointer
@ rule6 disable drop_cast exists @
identifier func, f1;
expression addr,exp1,exp2,src,size1,size2,offset,e1,e2;
position p1,p2;
type T1,T2;
@@
	func(...){
	...	
(
	copy_from_user(exp1, (T1)src.f1, size1)@p1
|
	copy_from_user(exp1, src.f1, size1)@p1
|
	copy_from_user(exp1, &(src.f1), size1)@p1
|
	__copy_from_user(exp1, (T1)src.f1, size1)@p1
|
	__copy_from_user(exp1, src.f1, size1)@p1
|
	__copy_from_user(exp1, &(src.f1), size1)@p1
)
	...	
		when != &src = addr
		when != &src ++
		when != &src --
		when != &src += offset	
		when != &src -= offset
		when != &src = &src + offset
		when != &src = &src - offset
		when != if (size2 > e1 || ...) { ... return ...; }
		when != if (size2 > e1 || ...) { ... size2 = e2 ... }
(
	__copy_from_user(exp2,(T2)&src,size2)@p2
|
	__copy_from_user(exp2,&src,size2)@p2
|
	copy_from_user(exp2,(T2)&src,size2)@p2
|
	copy_from_user(exp2,&src,size2)@p2
)
	... 
	}

@script:python depends on report@
p61 << rule6.p1;
p62 << rule6.p2;
s6 << rule6.src;
e6 << rule6.f1;
@@
if p61 and p62:
	post_match_process(6, p61, p62, s6, e6)
