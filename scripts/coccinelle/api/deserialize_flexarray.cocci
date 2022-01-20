// SPDX-License-Identifier: GPL-2.0-only
// Replace an open-coded "allocate flexible array struct, store count to
// member, and memcpy into flexible array" with mem_to_flex_dup() helper.
//
// Confidence: Moderate
// URL: http://coccinelle.lip6.fr/
// Options: --include-headers --very-quiet

virtual patch

@member_len_before depends on patch@
expression INSTANCE, COUNT, GFP, SRC, THING, STRUCT;
identifier MEMBER, STORED_COUNT;
@@
-INSTANCE->STORED_COUNT = COUNT;
 ...
-INSTANCE = \(kmalloc\|kzalloc\)(\(sizeof(\(*INSTANCE\|STRUCT\)) + COUNT\|sizeof(\(*INSTANCE\|STRUCT\)) + COUNT * sizeof(THING)\|struct_size(INSTANCE, MEMBER, COUNT)\),
+DECLARE_FLEX_ARRAY_ELEMENTS_COUNT(TYPE1, STORED_COUNT);
+DECLARE_FLEX_ARRAY_ELEMENTS(TYPE2, MEMBER);
+FIXMErc = mem_to_flex_dup(&INSTANCE, SRC, COUNT,
 	GFP)
 ...
(
-memcpy(INSTANCE->MEMBER, SRC, COUNT);
|
-memcpy(INSTANCE->MEMBER, SRC, COUNT * sizeof(THING));
|
-memcpy(INSTANCE->MEMBER, SRC, flex_array_size(INSTANCE, MEMBER, COUNT));
)

@member_len_middle depends on patch@
expression INSTANCE, COUNT, GFP, SRC, THING, STRUCT;
identifier MEMBER, STORED_COUNT;
@@
-INSTANCE = \(kmalloc\|kzalloc\)(\(sizeof(\(*INSTANCE\|STRUCT\)) + COUNT\|sizeof(\(*INSTANCE\|STRUCT\)) + COUNT * sizeof(THING)\|struct_size(INSTANCE, MEMBER, COUNT)\),
+DECLARE_FLEX_ARRAY_ELEMENTS_COUNT(TYPE1, STORED_COUNT);
+DECLARE_FLEX_ARRAY_ELEMENTS(TYPE2, MEMBER);
+FIXMErc = mem_to_flex_dup(&INSTANCE, SRC, COUNT,
 	GFP)
 ...
-INSTANCE->STORED_COUNT = COUNT;
 ...
(
-memcpy(INSTANCE->MEMBER, SRC, COUNT);
|
-memcpy(INSTANCE->MEMBER, SRC, COUNT * sizeof(THING));
|
-memcpy(INSTANCE->MEMBER, SRC, flex_array_size(INSTANCE, MEMBER, COUNT));
)

@member_len_after depends on patch@
expression INSTANCE, COUNT, GFP, SRC, THING, STRUCT;
identifier MEMBER, STORED_COUNT;
@@
-INSTANCE = \(kmalloc\|kzalloc\)(\(sizeof(\(*INSTANCE\|STRUCT\)) + COUNT\|sizeof(\(*INSTANCE\|STRUCT\)) + COUNT * sizeof(THING)\|struct_size(INSTANCE, MEMBER, COUNT)\),
+DECLARE_FLEX_ARRAY_ELEMENTS_COUNT(TYPE1, STORED_COUNT);
+DECLARE_FLEX_ARRAY_ELEMENTS(TYPE2, MEMBER);
+FIXMErc = mem_to_flex_dup(&INSTANCE, SRC, COUNT,
 	GFP)
 ...
(
-memcpy(INSTANCE->MEMBER, SRC, COUNT);
|
-memcpy(INSTANCE->MEMBER, SRC, COUNT * sizeof(THING));
|
-memcpy(INSTANCE->MEMBER, SRC, flex_array_size(INSTANCE, MEMBER, COUNT));
)
 ...
-INSTANCE->STORED_COUNT = COUNT;


@sub_member_len_before depends on patch@
expression INSTANCE, COUNT, GFP, SRC, THING, STRUCT;
identifier SUB, MEMBER, STORED_COUNT;
@@
-INSTANCE->SUB.STORED_COUNT = COUNT;
 ...
-INSTANCE = \(kmalloc\|kzalloc\)(\(sizeof(\(*INSTANCE\|STRUCT\)) + COUNT\|sizeof(\(*INSTANCE\|STRUCT\)) + COUNT * sizeof(THING)\|struct_size(INSTANCE, SUB.MEMBER, COUNT)\),
+DECLARE_FLEX_ARRAY_ELEMENTS_COUNT(TYPE1, STORED_COUNT);
+DECLARE_FLEX_ARRAY_ELEMENTS(TYPE2, MEMBER);
+FIXMErc = mem_to_flex_dup(&INSTANCE, SRC, COUNT,
 	GFP)
 ...
(
-memcpy(INSTANCE->SUB.MEMBER, SRC, COUNT);
|
-memcpy(INSTANCE->SUB.MEMBER, SRC, COUNT * sizeof(THING));
|
-memcpy(INSTANCE->SUB.MEMBER, SRC, flex_array_size(INSTANCE, SUB.MEMBER, COUNT));
)

@sub_member_len_middle depends on patch@
expression INSTANCE, COUNT, GFP, SRC, THING, STRUCT;
identifier SUB, MEMBER, STORED_COUNT;
@@
-INSTANCE = \(kmalloc\|kzalloc\)(\(sizeof(\(*INSTANCE\|STRUCT\)) + COUNT\|sizeof(\(*INSTANCE\|STRUCT\)) + COUNT * sizeof(THING)\|struct_size(INSTANCE, SUB.MEMBER, COUNT)\),
+DECLARE_FLEX_ARRAY_ELEMENTS_COUNT(TYPE1, STORED_COUNT);
+DECLARE_FLEX_ARRAY_ELEMENTS(TYPE2, MEMBER);
+FIXMErc = mem_to_flex_dup(&INSTANCE, SRC, COUNT,
 	GFP)
 ...
-INSTANCE->SUB.STORED_COUNT = COUNT;
 ...
(
-memcpy(INSTANCE->SUB.MEMBER, SRC, COUNT);
|
-memcpy(INSTANCE->SUB.MEMBER, SRC, COUNT * sizeof(THING));
|
-memcpy(INSTANCE->SUB.MEMBER, SRC, flex_array_size(INSTANCE, SUB.MEMBER, COUNT));
)

@sub_member_len_after depends on patch@
expression INSTANCE, COUNT, GFP, SRC, THING, STRUCT;
identifier SUB, MEMBER, STORED_COUNT;
@@
-INSTANCE = \(kmalloc\|kzalloc\)(\(sizeof(\(*INSTANCE\|STRUCT\)) + COUNT\|sizeof(\(*INSTANCE\|STRUCT\)) + COUNT * sizeof(THING)\|struct_size(INSTANCE, SUB.MEMBER, COUNT)\),
+DECLARE_FLEX_ARRAY_ELEMENTS_COUNT(TYPE1, STORED_COUNT);
+DECLARE_FLEX_ARRAY_ELEMENTS(TYPE2, MEMBER);
+FIXMErc = mem_to_flex_dup(&INSTANCE, SRC, COUNT,
 	GFP)
 ...
(
-memcpy(INSTANCE->SUB.MEMBER, SRC, COUNT);
|
-memcpy(INSTANCE->SUB.MEMBER, SRC, COUNT * sizeof(THING));
|
-memcpy(INSTANCE->SUB.MEMBER, SRC, flex_array_size(INSTANCE, SUB.MEMBER, COUNT));
)
 ...
-INSTANCE->SUB.STORED_COUNT = COUNT;
