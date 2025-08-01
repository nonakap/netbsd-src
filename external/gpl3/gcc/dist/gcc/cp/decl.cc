/* Process declarations and variables for -*- C++ -*- compiler.
   Copyright (C) 1988-2022 Free Software Foundation, Inc.
   Contributed by Michael Tiemann (tiemann@cygnus.com)

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

GCC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */


/* Process declarations and symbol lookup for C++ front end.
   Also constructs types; the standard scalar types at initialization,
   and structure, union, array and enum types when they are declared.  */

/* ??? not all decl nodes are given the most useful possible
   line numbers.  For example, the CONST_DECLs for enum values.  */

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "target.h"
#include "c-family/c-target.h"
#include "cp-tree.h"
#include "timevar.h"
#include "stringpool.h"
#include "cgraph.h"
#include "stor-layout.h"
#include "varasm.h"
#include "attribs.h"
#include "flags.h"
#include "tree-iterator.h"
#include "decl.h"
#include "intl.h"
#include "toplev.h"
#include "c-family/c-objc.h"
#include "c-family/c-pragma.h"
#include "c-family/c-ubsan.h"
#include "debug.h"
#include "plugin.h"
#include "builtins.h"
#include "gimplify.h"
#include "asan.h"
#include "gcc-rich-location.h"
#include "langhooks.h"
#include "context.h"  /* For 'g'.  */
#include "omp-general.h"
#include "omp-offload.h"  /* For offload_vars.  */
#include "opts.h"
#include "langhooks-def.h"  /* For lhd_simulate_record_decl  */

/* Possible cases of bad specifiers type used by bad_specifiers. */
enum bad_spec_place {
  BSP_VAR,    /* variable */
  BSP_PARM,   /* parameter */
  BSP_TYPE,   /* type */
  BSP_FIELD   /* field */
};

static const char *redeclaration_error_message (tree, tree);

static int decl_jump_unsafe (tree);
static void require_complete_types_for_parms (tree);
static tree grok_reference_init (tree, tree, tree, int);
static tree grokvardecl (tree, tree, tree, const cp_decl_specifier_seq *,
			 int, int, int, bool, int, tree, location_t);
static void check_static_variable_definition (tree, tree);
static void record_unknown_type (tree, const char *);
static int member_function_or_else (tree, tree, enum overload_flags);
static tree local_variable_p_walkfn (tree *, int *, void *);
static const char *tag_name (enum tag_types);
static tree lookup_and_check_tag (enum tag_types, tree, TAG_how, bool);
static void maybe_deduce_size_from_array_init (tree, tree);
static void layout_var_decl (tree);
static tree check_initializer (tree, tree, int, vec<tree, va_gc> **);
static void make_rtl_for_nonlocal_decl (tree, tree, const char *);
static void copy_type_enum (tree , tree);
static void check_function_type (tree, tree);
static void finish_constructor_body (void);
static void begin_destructor_body (void);
static void finish_destructor_body (void);
static void record_key_method_defined (tree);
static tree create_array_type_for_decl (tree, tree, tree, location_t);
static tree get_atexit_node (void);
static tree get_dso_handle_node (void);
static tree start_cleanup_fn (void);
static void end_cleanup_fn (void);
static tree cp_make_fname_decl (location_t, tree, int);
static void initialize_predefined_identifiers (void);
static tree check_special_function_return_type
       (special_function_kind, tree, tree, int, const location_t*);
static tree push_cp_library_fn (enum tree_code, tree, int);
static tree build_cp_library_fn (tree, enum tree_code, tree, int);
static void store_parm_decls (tree);
static void initialize_local_var (tree, tree);
static void expand_static_init (tree, tree);
static location_t smallest_type_location (const cp_decl_specifier_seq*);

/* The following symbols are subsumed in the cp_global_trees array, and
   listed here individually for documentation purposes.

   C++ extensions
	tree wchar_decl_node;

	tree vtable_entry_type;
	tree delta_type_node;
	tree __t_desc_type_node;

	tree class_type_node;
	tree unknown_type_node;

   Array type `vtable_entry_type[]'

	tree vtbl_type_node;
	tree vtbl_ptr_type_node;

   Namespaces,

	tree std_node;
	tree abi_node;

   A FUNCTION_DECL which can call `abort'.  Not necessarily the
   one that the user will declare, but sufficient to be called
   by routines that want to abort the program.

	tree abort_fndecl;

   Used by RTTI
	tree type_info_type_node, tinfo_decl_id, tinfo_decl_type;
	tree tinfo_var_id;  */

tree cp_global_trees[CPTI_MAX];

/* A list of objects which have constructors or destructors
   which reside in namespace scope.  The decl is stored in
   the TREE_VALUE slot and the initializer is stored
   in the TREE_PURPOSE slot.  */
tree static_aggregates;

/* Like static_aggregates, but for thread_local variables.  */
tree tls_aggregates;

/* A hash-map mapping from variable decls to the dynamic initializer for
   the decl.  This is currently only used by OpenMP.  */
decl_tree_map *dynamic_initializers;

/* -- end of C++ */

/* A node for the integer constant 2.  */

tree integer_two_node;

/* vector of static decls.  */
vec<tree, va_gc> *static_decls;

/* vector of keyed classes.  */
vec<tree, va_gc> *keyed_classes;

/* Used only for jumps to as-yet undefined labels, since jumps to
   defined labels can have their validity checked immediately.  */

struct GTY((chain_next ("%h.next"))) named_label_use_entry {
  struct named_label_use_entry *next;
  /* The binding level to which this entry is *currently* attached.
     This is initially the binding level in which the goto appeared,
     but is modified as scopes are closed.  */
  cp_binding_level *binding_level;
  /* The head of the names list that was current when the goto appeared,
     or the inner scope popped.  These are the decls that will *not* be
     skipped when jumping to the label.  */
  tree names_in_scope;
  /* The location of the goto, for error reporting.  */
  location_t o_goto_locus;
  /* True if an OpenMP structured block scope has been closed since
     the goto appeared.  This means that the branch from the label will
     illegally exit an OpenMP scope.  */
  bool in_omp_scope;
};

/* A list of all LABEL_DECLs in the function that have names.  Here so
   we can clear out their names' definitions at the end of the
   function, and so we can check the validity of jumps to these labels.  */

struct GTY((for_user)) named_label_entry {

  tree name;  /* Name of decl. */

  tree label_decl; /* LABEL_DECL, unless deleted local label. */

  named_label_entry *outer; /* Outer shadowed chain.  */

  /* The binding level to which the label is *currently* attached.
     This is initially set to the binding level in which the label
     is defined, but is modified as scopes are closed.  */
  cp_binding_level *binding_level;

  /* The head of the names list that was current when the label was
     defined, or the inner scope popped.  These are the decls that will
     be skipped when jumping to the label.  */
  tree names_in_scope;

  /* A vector of all decls from all binding levels that would be
     crossed by a backward branch to the label.  */
  vec<tree, va_gc> *bad_decls;

  /* A list of uses of the label, before the label is defined.  */
  named_label_use_entry *uses;

  /* The following bits are set after the label is defined, and are
     updated as scopes are popped.  They indicate that a jump to the
     label will illegally enter a scope of the given flavor.  */
  bool in_try_scope;
  bool in_catch_scope;
  bool in_omp_scope;
  bool in_transaction_scope;
  bool in_constexpr_if;
  bool in_consteval_if;
};

#define named_labels cp_function_chain->x_named_labels

/* The number of function bodies which we are currently processing.
   (Zero if we are at namespace scope, one inside the body of a
   function, two inside the body of a function in a local class, etc.)  */
int function_depth;

/* Whether the exception-specifier is part of a function type (i.e. C++17).  */
bool flag_noexcept_type;

/* States indicating how grokdeclarator() should handle declspecs marked
   with __attribute__((deprecated)).  An object declared as
   __attribute__((deprecated)) suppresses warnings of uses of other
   deprecated items.  */
enum deprecated_states deprecated_state = DEPRECATED_NORMAL;


/* A list of VAR_DECLs whose type was incomplete at the time the
   variable was declared.  */

struct GTY(()) incomplete_var {
  tree decl;
  tree incomplete_type;
};


static GTY(()) vec<incomplete_var, va_gc> *incomplete_vars;

/* Returns the kind of template specialization we are currently
   processing, given that it's declaration contained N_CLASS_SCOPES
   explicit scope qualifications.  */

tmpl_spec_kind
current_tmpl_spec_kind (int n_class_scopes)
{
  int n_template_parm_scopes = 0;
  int seen_specialization_p = 0;
  int innermost_specialization_p = 0;
  cp_binding_level *b;

  /* Scan through the template parameter scopes.  */
  for (b = current_binding_level;
       b->kind == sk_template_parms;
       b = b->level_chain)
    {
      /* If we see a specialization scope inside a parameter scope,
	 then something is wrong.  That corresponds to a declaration
	 like:

	    template <class T> template <> ...

	 which is always invalid since [temp.expl.spec] forbids the
	 specialization of a class member template if the enclosing
	 class templates are not explicitly specialized as well.  */
      if (b->explicit_spec_p)
	{
	  if (n_template_parm_scopes == 0)
	    innermost_specialization_p = 1;
	  else
	    seen_specialization_p = 1;
	}
      else if (seen_specialization_p == 1)
	return tsk_invalid_member_spec;

      ++n_template_parm_scopes;
    }

  /* Handle explicit instantiations.  */
  if (processing_explicit_instantiation)
    {
      if (n_template_parm_scopes != 0)
	/* We've seen a template parameter list during an explicit
	   instantiation.  For example:

	     template <class T> template void f(int);

	   This is erroneous.  */
	return tsk_invalid_expl_inst;
      else
	return tsk_expl_inst;
    }

  if (n_template_parm_scopes < n_class_scopes)
    /* We've not seen enough template headers to match all the
       specialized classes present.  For example:

	 template <class T> void R<T>::S<T>::f(int);

       This is invalid; there needs to be one set of template
       parameters for each class.  */
    return tsk_insufficient_parms;
  else if (n_template_parm_scopes == n_class_scopes)
    /* We're processing a non-template declaration (even though it may
       be a member of a template class.)  For example:

	 template <class T> void S<T>::f(int);

       The `class T' matches the `S<T>', leaving no template headers
       corresponding to the `f'.  */
    return tsk_none;
  else if (n_template_parm_scopes > n_class_scopes + 1)
    /* We've got too many template headers.  For example:

	 template <> template <class T> void f (T);

       There need to be more enclosing classes.  */
    return tsk_excessive_parms;
  else
    /* This must be a template.  It's of the form:

	 template <class T> template <class U> void S<T>::f(U);

       This is a specialization if the innermost level was a
       specialization; otherwise it's just a definition of the
       template.  */
    return innermost_specialization_p ? tsk_expl_spec : tsk_template;
}

/* Exit the current scope.  */

void
finish_scope (void)
{
  poplevel (0, 0, 0);
}

/* When a label goes out of scope, check to see if that label was used
   in a valid manner, and issue any appropriate warnings or errors.  */

static void
check_label_used (tree label)
{
  if (!processing_template_decl)
    {
      if (DECL_INITIAL (label) == NULL_TREE)
	{
	  location_t location;

	  error ("label %q+D used but not defined", label);
	  location = input_location;
	    /* FIXME want (LOCATION_FILE (input_location), (line)0) */
	  /* Avoid crashing later.  */
	  define_label (location, DECL_NAME (label));
	}
      else 
	warn_for_unused_label (label);
    }
}

/* Helper function to sort named label entries in a vector by DECL_UID.  */

static int
sort_labels (const void *a, const void *b)
{
  tree label1 = *(tree const *) a;
  tree label2 = *(tree const *) b;

  /* DECL_UIDs can never be equal.  */
  return DECL_UID (label1) > DECL_UID (label2) ? -1 : +1;
}

/* At the end of a function, all labels declared within the function
   go out of scope.  BLOCK is the top-level block for the
   function.  */

static void
pop_labels (tree block)
{
  if (!named_labels)
    return;

  /* We need to add the labels to the block chain, so debug
     information is emitted.  But, we want the order to be stable so
     need to sort them first.  Otherwise the debug output could be
     randomly ordered.  I guess it's mostly stable, unless the hash
     table implementation changes.  */
  auto_vec<tree, 32> labels (named_labels->elements ());
  hash_table<named_label_hash>::iterator end (named_labels->end ());
  for (hash_table<named_label_hash>::iterator iter
	 (named_labels->begin ()); iter != end; ++iter)
    {
      named_label_entry *ent = *iter;

      gcc_checking_assert (!ent->outer);
      if (ent->label_decl)
	labels.quick_push (ent->label_decl);
      ggc_free (ent);
    }
  named_labels = NULL;
  labels.qsort (sort_labels);

  while (labels.length ())
    {
      tree label = labels.pop ();

      DECL_CHAIN (label) = BLOCK_VARS (block);
      BLOCK_VARS (block) = label;

      check_label_used (label);
    }
}

/* At the end of a block with local labels, restore the outer definition.  */

static void
pop_local_label (tree id, tree label)
{
  check_label_used (label);
  named_label_entry **slot = named_labels->find_slot_with_hash
    (id, IDENTIFIER_HASH_VALUE (id), NO_INSERT);
  named_label_entry *ent = *slot;

  if (ent->outer)
    ent = ent->outer;
  else
    {
      ent = ggc_cleared_alloc<named_label_entry> ();
      ent->name = id;
    }
  *slot = ent;
}

/* The following two routines are used to interface to Objective-C++.
   The binding level is purposely treated as an opaque type.  */

void *
objc_get_current_scope (void)
{
  return current_binding_level;
}

/* The following routine is used by the NeXT-style SJLJ exceptions;
   variables get marked 'volatile' so as to not be clobbered by
   _setjmp()/_longjmp() calls.  All variables in the current scope,
   as well as parent scopes up to (but not including) ENCLOSING_BLK
   shall be thusly marked.  */

void
objc_mark_locals_volatile (void *enclosing_blk)
{
  cp_binding_level *scope;

  for (scope = current_binding_level;
       scope && scope != enclosing_blk;
       scope = scope->level_chain)
    {
      tree decl;

      for (decl = scope->names; decl; decl = TREE_CHAIN (decl))
	objc_volatilize_decl (decl);

      /* Do not climb up past the current function.  */
      if (scope->kind == sk_function_parms)
	break;
    }
}

/* True if B is the level for the condition of a constexpr if.  */

static bool
level_for_constexpr_if (cp_binding_level *b)
{
  return (b->kind == sk_cond && b->this_entity
	  && TREE_CODE (b->this_entity) == IF_STMT
	  && IF_STMT_CONSTEXPR_P (b->this_entity));
}

/* True if B is the level for the condition of a consteval if.  */

static bool
level_for_consteval_if (cp_binding_level *b)
{
  return (b->kind == sk_cond && b->this_entity
	  && TREE_CODE (b->this_entity) == IF_STMT
	  && IF_STMT_CONSTEVAL_P (b->this_entity));
}

/* Update data for defined and undefined labels when leaving a scope.  */

int
poplevel_named_label_1 (named_label_entry **slot, cp_binding_level *bl)
{
  named_label_entry *ent = *slot;
  cp_binding_level *obl = bl->level_chain;

  if (ent->binding_level == bl)
    {
      tree decl;

      /* ENT->NAMES_IN_SCOPE may contain a mixture of DECLs and
	 TREE_LISTs representing OVERLOADs, so be careful.  */
      for (decl = ent->names_in_scope; decl; decl = (DECL_P (decl)
						     ? DECL_CHAIN (decl)
						     : TREE_CHAIN (decl)))
	if (decl_jump_unsafe (decl))
	  vec_safe_push (ent->bad_decls, decl);

      ent->binding_level = obl;
      ent->names_in_scope = obl->names;
      switch (bl->kind)
	{
	case sk_try:
	  ent->in_try_scope = true;
	  break;
	case sk_catch:
	  ent->in_catch_scope = true;
	  break;
	case sk_omp:
	  ent->in_omp_scope = true;
	  break;
	case sk_transaction:
	  ent->in_transaction_scope = true;
	  break;
	case sk_block:
	  if (level_for_constexpr_if (bl->level_chain))
	    ent->in_constexpr_if = true;
	  else if (level_for_consteval_if (bl->level_chain))
	    ent->in_consteval_if = true;
	  break;
	default:
	  break;
	}
    }
  else if (ent->uses)
    {
      struct named_label_use_entry *use;

      for (use = ent->uses; use ; use = use->next)
	if (use->binding_level == bl)
	  {
	    use->binding_level = obl;
	    use->names_in_scope = obl->names;
	    if (bl->kind == sk_omp)
	      use->in_omp_scope = true;
	  }
    }

  return 1;
}

/* Saved errorcount to avoid -Wunused-but-set-{parameter,variable} warnings
   when errors were reported, except for -Werror-unused-but-set-*.  */
static int unused_but_set_errorcount;

/* Exit a binding level.
   Pop the level off, and restore the state of the identifier-decl mappings
   that were in effect when this level was entered.

   If KEEP == 1, this level had explicit declarations, so
   and create a "block" (a BLOCK node) for the level
   to record its declarations and subblocks for symbol table output.

   If FUNCTIONBODY is nonzero, this level is the body of a function,
   so create a block as if KEEP were set and also clear out all
   label names.

   If REVERSE is nonzero, reverse the order of decls before putting
   them into the BLOCK.  */

tree
poplevel (int keep, int reverse, int functionbody)
{
  tree link;
  /* The chain of decls was accumulated in reverse order.
     Put it into forward order, just for cleanliness.  */
  tree decls;
  tree subblocks;
  tree block;
  tree decl;
  scope_kind kind;

  auto_cond_timevar tv (TV_NAME_LOOKUP);
 restart:

  block = NULL_TREE;

  gcc_assert (current_binding_level->kind != sk_class
	      && current_binding_level->kind != sk_namespace);

  if (current_binding_level->kind == sk_cleanup)
    functionbody = 0;
  subblocks = functionbody >= 0 ? current_binding_level->blocks : 0;

  gcc_assert (!vec_safe_length (current_binding_level->class_shadowed));

  /* We used to use KEEP == 2 to indicate that the new block should go
     at the beginning of the list of blocks at this binding level,
     rather than the end.  This hack is no longer used.  */
  gcc_assert (keep == 0 || keep == 1);

  if (current_binding_level->keep)
    keep = 1;

  /* Any uses of undefined labels, and any defined labels, now operate
     under constraints of next binding contour.  */
  if (cfun && !functionbody && named_labels)
    named_labels->traverse<cp_binding_level *, poplevel_named_label_1>
		   (current_binding_level);

  /* Get the decls in the order they were written.
     Usually current_binding_level->names is in reverse order.
     But parameter decls were previously put in forward order.  */

  decls = current_binding_level->names;
  if (reverse)
    {
      decls = nreverse (decls);
      current_binding_level->names = decls;
    }

  /* If there were any declarations or structure tags in that level,
     or if this level is a function body,
     create a BLOCK to record them for the life of this function.  */
  block = NULL_TREE;
  /* Avoid function body block if possible.  */
  if (functionbody && subblocks && BLOCK_CHAIN (subblocks) == NULL_TREE)
    keep = 0;
  else if (keep == 1 || functionbody)
    block = make_node (BLOCK);
  if (block != NULL_TREE)
    {
      BLOCK_VARS (block) = decls;
      BLOCK_SUBBLOCKS (block) = subblocks;
    }

  /* In each subblock, record that this is its superior.  */
  if (keep >= 0)
    for (link = subblocks; link; link = BLOCK_CHAIN (link))
      BLOCK_SUPERCONTEXT (link) = block;

  /* Before we remove the declarations first check for unused variables.  */
  if ((warn_unused_variable || warn_unused_but_set_variable)
      && current_binding_level->kind != sk_template_parms
      && !processing_template_decl)
    for (tree d = get_local_decls (); d; d = TREE_CHAIN (d))
      {
	/* There are cases where D itself is a TREE_LIST.  See in
	   push_local_binding where the list of decls returned by
	   getdecls is built.  */
	decl = TREE_CODE (d) == TREE_LIST ? TREE_VALUE (d) : d;

	tree type = TREE_TYPE (decl);
	if (VAR_P (decl)
	    && (! TREE_USED (decl) || !DECL_READ_P (decl))
	    && ! DECL_IN_SYSTEM_HEADER (decl)
	    /* For structured bindings, consider only real variables, not
	       subobjects.  */
	    && (DECL_DECOMPOSITION_P (decl) ? !DECL_DECOMP_BASE (decl)
		: (DECL_NAME (decl) && !DECL_ARTIFICIAL (decl)))
	    && type != error_mark_node
	    && (!CLASS_TYPE_P (type)
		|| !TYPE_HAS_NONTRIVIAL_DESTRUCTOR (type)
		|| lookup_attribute ("warn_unused",
				     TYPE_ATTRIBUTES (TREE_TYPE (decl)))))
	  {
	    if (! TREE_USED (decl))
	      {
		if (!DECL_NAME (decl) && DECL_DECOMPOSITION_P (decl))
		  warning_at (DECL_SOURCE_LOCATION (decl),
			      OPT_Wunused_variable,
			      "unused structured binding declaration");
		else
		  warning_at (DECL_SOURCE_LOCATION (decl),
			      OPT_Wunused_variable, "unused variable %qD", decl);
		suppress_warning (decl, OPT_Wunused_variable);
	      }
	    else if (DECL_CONTEXT (decl) == current_function_decl
		     // For -Wunused-but-set-variable leave references alone.
		     && !TYPE_REF_P (TREE_TYPE (decl))
		     && errorcount == unused_but_set_errorcount)
	      {
		if (!DECL_NAME (decl) && DECL_DECOMPOSITION_P (decl))
		  warning_at (DECL_SOURCE_LOCATION (decl),
			      OPT_Wunused_but_set_variable, "structured "
			      "binding declaration set but not used");
		else
		  warning_at (DECL_SOURCE_LOCATION (decl),
			      OPT_Wunused_but_set_variable,
			      "variable %qD set but not used", decl);
		unused_but_set_errorcount = errorcount;
	      }
	  }
      }

  /* Remove declarations for all the DECLs in this level.  */
  for (link = decls; link; link = TREE_CHAIN (link))
    {
      tree name;
      if (TREE_CODE (link) == TREE_LIST)
	{
	  decl = TREE_VALUE (link);
	  name = TREE_PURPOSE (link);
	  gcc_checking_assert (name);
	}
      else
	{
	  decl = link;
	  name = DECL_NAME (decl);
	}

      /* Remove the binding.  */
      if (TREE_CODE (decl) == LABEL_DECL)
	pop_local_label (name, decl);
      else
	pop_local_binding (name, decl);
    }

  /* Restore the IDENTIFIER_TYPE_VALUEs.  */
  for (link = current_binding_level->type_shadowed;
       link; link = TREE_CHAIN (link))
    SET_IDENTIFIER_TYPE_VALUE (TREE_PURPOSE (link), TREE_VALUE (link));

  /* There may be OVERLOADs (wrapped in TREE_LISTs) on the BLOCK_VARs
     list if a `using' declaration put them there.  The debugging
     back ends won't understand OVERLOAD, so we remove them here.
     Because the BLOCK_VARS are (temporarily) shared with
     CURRENT_BINDING_LEVEL->NAMES we must do this fixup after we have
     popped all the bindings.  Also remove undeduced 'auto' decls,
     which LTO doesn't understand, and can't have been used by anything.  */
  if (block)
    {
      tree* d;

      for (d = &BLOCK_VARS (block); *d; )
	{
	  if (TREE_CODE (*d) == TREE_LIST
	      || (!processing_template_decl
		  && undeduced_auto_decl (*d)))
	    *d = TREE_CHAIN (*d);
	  else
	    d = &DECL_CHAIN (*d);
	}
    }

  /* If the level being exited is the top level of a function,
     check over all the labels.  */
  if (functionbody)
    {
      if (block)
	{
	  /* Since this is the top level block of a function, the vars are
	     the function's parameters.  Don't leave them in the BLOCK
	     because they are found in the FUNCTION_DECL instead.  */
	  BLOCK_VARS (block) = 0;
	  pop_labels (block);
	}
      else
	pop_labels (subblocks);
    }

  kind = current_binding_level->kind;
  if (kind == sk_cleanup)
    {
      tree stmt;

      /* If this is a temporary binding created for a cleanup, then we'll
	 have pushed a statement list level.  Pop that, create a new
	 BIND_EXPR for the block, and insert it into the stream.  */
      stmt = pop_stmt_list (current_binding_level->statement_list);
      stmt = c_build_bind_expr (input_location, block, stmt);
      add_stmt (stmt);
    }

  leave_scope ();
  if (functionbody)
    {
      /* The current function is being defined, so its DECL_INITIAL
	 should be error_mark_node.  */
      gcc_assert (DECL_INITIAL (current_function_decl) == error_mark_node);
      DECL_INITIAL (current_function_decl) = block ? block : subblocks;
      if (subblocks)
	{
	  if (FUNCTION_NEEDS_BODY_BLOCK (current_function_decl))
	    {
	      if (BLOCK_SUBBLOCKS (subblocks))
		BLOCK_OUTER_CURLY_BRACE_P (BLOCK_SUBBLOCKS (subblocks)) = 1;
	    }
	  else
	    BLOCK_OUTER_CURLY_BRACE_P (subblocks) = 1;
	}
    }
  else if (block)
    current_binding_level->blocks
      = block_chainon (current_binding_level->blocks, block);

  /* If we did not make a block for the level just exited,
     any blocks made for inner levels
     (since they cannot be recorded as subblocks in that level)
     must be carried forward so they will later become subblocks
     of something else.  */
  else if (subblocks)
    current_binding_level->blocks
      = block_chainon (current_binding_level->blocks, subblocks);

  /* Each and every BLOCK node created here in `poplevel' is important
     (e.g. for proper debugging information) so if we created one
     earlier, mark it as "used".  */
  if (block)
    TREE_USED (block) = 1;

  /* All temporary bindings created for cleanups are popped silently.  */
  if (kind == sk_cleanup)
    goto restart;

  return block;
}

/* Call wrapup_globals_declarations for the globals in NAMESPACE.  */
/* Diagnose odr-used extern inline variables without definitions
   in the current TU.  */

int
wrapup_namespace_globals ()
{
  if (vec<tree, va_gc> *statics = static_decls)
    {
      for (tree decl : *statics)
	{
	  if (warn_unused_function
	      && TREE_CODE (decl) == FUNCTION_DECL
	      && DECL_INITIAL (decl) == 0
	      && DECL_EXTERNAL (decl)
	      && !TREE_PUBLIC (decl)
	      && !DECL_ARTIFICIAL (decl)
	      && !DECL_FRIEND_PSEUDO_TEMPLATE_INSTANTIATION (decl)
	      && !warning_suppressed_p (decl, OPT_Wunused_function))
	    warning_at (DECL_SOURCE_LOCATION (decl),
			OPT_Wunused_function,
			"%qF declared %<static%> but never defined", decl);

	  if (VAR_P (decl)
	      && DECL_EXTERNAL (decl)
	      && DECL_INLINE_VAR_P (decl)
	      && DECL_ODR_USED (decl))
	    error_at (DECL_SOURCE_LOCATION (decl),
		      "odr-used inline variable %qD is not defined", decl);
	}

      /* Clear out the list, so we don't rescan next time.  */
      static_decls = NULL;

      /* Write out any globals that need to be output.  */
      return wrapup_global_declarations (statics->address (),
					 statics->length ());
    }
  return 0;
}

/* In C++, you don't have to write `struct S' to refer to `S'; you
   can just use `S'.  We accomplish this by creating a TYPE_DECL as
   if the user had written `typedef struct S S'.  Create and return
   the TYPE_DECL for TYPE.  */

tree
create_implicit_typedef (tree name, tree type)
{
  tree decl;

  decl = build_decl (input_location, TYPE_DECL, name, type);
  DECL_ARTIFICIAL (decl) = 1;
  /* There are other implicit type declarations, like the one *within*
     a class that allows you to write `S::S'.  We must distinguish
     amongst these.  */
  SET_DECL_IMPLICIT_TYPEDEF_P (decl);
  TYPE_NAME (type) = decl;
  TYPE_STUB_DECL (type) = decl;

  return decl;
}

/* Function-scope local entities that need discriminators.  Each entry
   is a {decl,name} pair.  VAR_DECLs for anon unions get their name
   smashed, so we cannot rely on DECL_NAME.  */

static GTY((deletable)) vec<tree, va_gc> *local_entities;

/* Determine the mangling discriminator of local DECL.  There are
   generally very few of these in any particular function.  */

void
determine_local_discriminator (tree decl)
{
  auto_cond_timevar tv (TV_NAME_LOOKUP);
  retrofit_lang_decl (decl);
  tree ctx = DECL_CONTEXT (decl);
  tree name = (TREE_CODE (decl) == TYPE_DECL
	       && TYPE_UNNAMED_P (TREE_TYPE (decl))
	       ? NULL_TREE : DECL_NAME (decl));
  size_t nelts = vec_safe_length (local_entities);
  for (size_t i = 0; i < nelts; i += 2)
    {
      tree *pair = &(*local_entities)[i];
      tree d = pair[0];
      tree n = pair[1];
      gcc_checking_assert (d != decl);
      if (name == n
	  && TREE_CODE (decl) == TREE_CODE (d)
	  && ctx == DECL_CONTEXT (d))
	{
	  tree disc = integer_one_node;
	  if (DECL_DISCRIMINATOR (d))
	    disc = build_int_cst (TREE_TYPE (disc),
				  TREE_INT_CST_LOW (DECL_DISCRIMINATOR (d)) + 1);
	  DECL_DISCRIMINATOR (decl) = disc;
	  /* Replace the saved decl.  */
	  pair[0] = decl;
	  decl = NULL_TREE;
	  break;
	}
    }

  if (decl)
    {
      vec_safe_reserve (local_entities, 2);
      local_entities->quick_push (decl);
      local_entities->quick_push (name);
    }
}



/* Returns true if functions FN1 and FN2 have equivalent trailing
   requires clauses.  */

static bool
function_requirements_equivalent_p (tree newfn, tree oldfn)
{
  /* In the concepts TS, the combined constraints are compared.  */
  if (cxx_dialect < cxx20)
    {
      tree ci1 = get_constraints (oldfn);
      tree ci2 = get_constraints (newfn);
      tree req1 = ci1 ? CI_ASSOCIATED_CONSTRAINTS (ci1) : NULL_TREE;
      tree req2 = ci2 ? CI_ASSOCIATED_CONSTRAINTS (ci2) : NULL_TREE;
      return cp_tree_equal (req1, req2);
    }

  /* Compare only trailing requirements.  */
  tree reqs1 = get_trailing_function_requirements (newfn);
  tree reqs2 = get_trailing_function_requirements (oldfn);
  if ((reqs1 != NULL_TREE) != (reqs2 != NULL_TREE))
    return false;

  /* Substitution is needed when friends are involved.  */
  reqs1 = maybe_substitute_reqs_for (reqs1, newfn);
  reqs2 = maybe_substitute_reqs_for (reqs2, oldfn);

  return cp_tree_equal (reqs1, reqs2);
}

/* Subroutine of duplicate_decls: return truthvalue of whether
   or not types of these decls match.

   For C++, we must compare the parameter list so that `int' can match
   `int&' in a parameter position, but `int&' is not confused with
   `const int&'.  */

int
decls_match (tree newdecl, tree olddecl, bool record_versions /* = true */)
{
  int types_match;

  if (newdecl == olddecl)
    return 1;

  if (TREE_CODE (newdecl) != TREE_CODE (olddecl))
    /* If the two DECLs are not even the same kind of thing, we're not
       interested in their types.  */
    return 0;

  gcc_assert (DECL_P (newdecl));

  if (TREE_CODE (newdecl) == FUNCTION_DECL)
    {
      /* Specializations of different templates are different functions
	 even if they have the same type.  */
      tree t1 = (DECL_USE_TEMPLATE (newdecl)
		 ? DECL_TI_TEMPLATE (newdecl)
		 : NULL_TREE);
      tree t2 = (DECL_USE_TEMPLATE (olddecl)
		 ? DECL_TI_TEMPLATE (olddecl)
		 : NULL_TREE);
      if (t1 != t2)
	return 0;

      if (CP_DECL_CONTEXT (newdecl) != CP_DECL_CONTEXT (olddecl)
	  && ! (DECL_EXTERN_C_P (newdecl)
		&& DECL_EXTERN_C_P (olddecl)))
	return 0;

      /* A new declaration doesn't match a built-in one unless it
	 is also extern "C".  */
      if (DECL_IS_UNDECLARED_BUILTIN (olddecl)
	  && DECL_EXTERN_C_P (olddecl) && !DECL_EXTERN_C_P (newdecl))
	return 0;

      tree f1 = TREE_TYPE (newdecl);
      tree f2 = TREE_TYPE (olddecl);
      if (TREE_CODE (f1) != TREE_CODE (f2))
	return 0;

      /* A declaration with deduced return type should use its pre-deduction
	 type for declaration matching.  */
      tree r2 = fndecl_declared_return_type (olddecl);
      tree r1 = fndecl_declared_return_type (newdecl);

      tree p1 = TYPE_ARG_TYPES (f1);
      tree p2 = TYPE_ARG_TYPES (f2);

      if (same_type_p (r1, r2))
	{
	  if (!prototype_p (f2) && DECL_EXTERN_C_P (olddecl)
	      && fndecl_built_in_p (olddecl))
	    {
	      types_match = self_promoting_args_p (p1);
	      if (p1 == void_list_node)
		TREE_TYPE (newdecl) = TREE_TYPE (olddecl);
	    }
	  else
	    types_match =
	      compparms (p1, p2)
	      && type_memfn_rqual (f1) == type_memfn_rqual (f2)
	      && (TYPE_ATTRIBUTES (TREE_TYPE (newdecl)) == NULL_TREE
	          || comp_type_attributes (TREE_TYPE (newdecl),
					   TREE_TYPE (olddecl)) != 0);
	}
      else
	types_match = 0;

      /* Two function declarations match if either has a requires-clause
         then both have a requires-clause and their constraints-expressions
         are equivalent.  */
      if (types_match && flag_concepts)
	types_match = function_requirements_equivalent_p (newdecl, olddecl);

      /* The decls dont match if they correspond to two different versions
	 of the same function.   Disallow extern "C" functions to be
	 versions for now.  */
      if (types_match
	  && !DECL_EXTERN_C_P (newdecl)
	  && !DECL_EXTERN_C_P (olddecl)
	  && targetm.target_option.function_versions (newdecl, olddecl))
	{
	  if (record_versions)
	    maybe_version_functions (newdecl, olddecl,
				     (!DECL_FUNCTION_VERSIONED (newdecl)
				      || !DECL_FUNCTION_VERSIONED (olddecl)));
	  return 0;
	}
    }
  else if (TREE_CODE (newdecl) == TEMPLATE_DECL)
    {
      if (!template_heads_equivalent_p (newdecl, olddecl))
	return 0;

      tree oldres = DECL_TEMPLATE_RESULT (olddecl);
      tree newres = DECL_TEMPLATE_RESULT (newdecl);

      if (TREE_CODE (newres) != TREE_CODE (oldres))
	return 0;

      /* Two template types match if they are the same. Otherwise, compare
         the underlying declarations.  */
      if (TREE_CODE (newres) == TYPE_DECL)
        types_match = same_type_p (TREE_TYPE (newres), TREE_TYPE (oldres));
      else
	types_match = decls_match (newres, oldres);
    }
  else
    {
      /* Need to check scope for variable declaration (VAR_DECL).
	 For typedef (TYPE_DECL), scope is ignored.  */
      if (VAR_P (newdecl)
	  && CP_DECL_CONTEXT (newdecl) != CP_DECL_CONTEXT (olddecl)
	  /* [dcl.link]
	     Two declarations for an object with C language linkage
	     with the same name (ignoring the namespace that qualify
	     it) that appear in different namespace scopes refer to
	     the same object.  */
	  && !(DECL_EXTERN_C_P (olddecl) && DECL_EXTERN_C_P (newdecl)))
	return 0;

      if (TREE_TYPE (newdecl) == error_mark_node)
	types_match = TREE_TYPE (olddecl) == error_mark_node;
      else if (TREE_TYPE (olddecl) == NULL_TREE)
	types_match = TREE_TYPE (newdecl) == NULL_TREE;
      else if (TREE_TYPE (newdecl) == NULL_TREE)
	types_match = 0;
      else
	types_match = comptypes (TREE_TYPE (newdecl),
				 TREE_TYPE (olddecl),
				 COMPARE_REDECLARATION);
    }

  return types_match;
}

/* Mark DECL as versioned if it isn't already.  */

static void
maybe_mark_function_versioned (tree decl)
{
  if (!DECL_FUNCTION_VERSIONED (decl))
    {
      DECL_FUNCTION_VERSIONED (decl) = 1;
      /* If DECL_ASSEMBLER_NAME has already been set, re-mangle
	 to include the version marker.  */
      if (DECL_ASSEMBLER_NAME_SET_P (decl))
	mangle_decl (decl);
    }
}

/* NEWDECL and OLDDECL have identical signatures.  If they are
   different versions adjust them and return true.
   If RECORD is set to true, record function versions.  */

bool
maybe_version_functions (tree newdecl, tree olddecl, bool record)
{
  if (!targetm.target_option.function_versions (newdecl, olddecl))
    return false;

  maybe_mark_function_versioned (olddecl);
  if (DECL_LOCAL_DECL_P (olddecl))
    {
      olddecl = DECL_LOCAL_DECL_ALIAS (olddecl);
      maybe_mark_function_versioned (olddecl);
    }

  maybe_mark_function_versioned (newdecl);
  if (DECL_LOCAL_DECL_P (newdecl))
    {
      /* Unfortunately, we can get here before pushdecl naturally calls
	 push_local_extern_decl_alias, so we need to call it directly.  */
      if (!DECL_LOCAL_DECL_ALIAS (newdecl))
	push_local_extern_decl_alias (newdecl);
      newdecl = DECL_LOCAL_DECL_ALIAS (newdecl);
      maybe_mark_function_versioned (newdecl);
    }

  if (record)
    cgraph_node::record_function_versions (olddecl, newdecl);

  return true;
}

/* If NEWDECL is `static' and an `extern' was seen previously,
   warn about it.  OLDDECL is the previous declaration.

   Note that this does not apply to the C++ case of declaring
   a variable `extern const' and then later `const'.

   Don't complain about built-in functions, since they are beyond
   the user's control.  */

void
warn_extern_redeclared_static (tree newdecl, tree olddecl)
{
  if (TREE_CODE (newdecl) == TYPE_DECL
      || TREE_CODE (newdecl) == TEMPLATE_DECL
      || TREE_CODE (newdecl) == CONST_DECL
      || TREE_CODE (newdecl) == NAMESPACE_DECL)
    return;

  /* Don't get confused by static member functions; that's a different
     use of `static'.  */
  if (TREE_CODE (newdecl) == FUNCTION_DECL
      && DECL_STATIC_FUNCTION_P (newdecl))
    return;

  /* If the old declaration was `static', or the new one isn't, then
     everything is OK.  */
  if (DECL_THIS_STATIC (olddecl) || !DECL_THIS_STATIC (newdecl))
    return;

  /* It's OK to declare a builtin function as `static'.  */
  if (TREE_CODE (olddecl) == FUNCTION_DECL
      && DECL_ARTIFICIAL (olddecl))
    return;

  auto_diagnostic_group d;
  if (permerror (DECL_SOURCE_LOCATION (newdecl),
		 "%qD was declared %<extern%> and later %<static%>", newdecl))
    inform (DECL_SOURCE_LOCATION (olddecl),
	    "previous declaration of %qD", olddecl);
}

/* NEW_DECL is a redeclaration of OLD_DECL; both are functions or
   function templates.  If their exception specifications do not
   match, issue a diagnostic.  */

static void
check_redeclaration_exception_specification (tree new_decl,
					     tree old_decl)
{
  tree new_exceptions = TYPE_RAISES_EXCEPTIONS (TREE_TYPE (new_decl));
  tree old_exceptions = TYPE_RAISES_EXCEPTIONS (TREE_TYPE (old_decl));

  /* Two default specs are equivalent, don't force evaluation.  */
  if (UNEVALUATED_NOEXCEPT_SPEC_P (new_exceptions)
      && UNEVALUATED_NOEXCEPT_SPEC_P (old_exceptions))
    return;

  if (!type_dependent_expression_p (old_decl))
    {
      maybe_instantiate_noexcept (new_decl);
      maybe_instantiate_noexcept (old_decl);
    }
  new_exceptions = TYPE_RAISES_EXCEPTIONS (TREE_TYPE (new_decl));
  old_exceptions = TYPE_RAISES_EXCEPTIONS (TREE_TYPE (old_decl));

  /* [except.spec]

     If any declaration of a function has an exception-specification,
     all declarations, including the definition and an explicit
     specialization, of that function shall have an
     exception-specification with the same set of type-ids.  */
  if (!DECL_IS_UNDECLARED_BUILTIN (old_decl)
      && !DECL_IS_UNDECLARED_BUILTIN (new_decl)
      && !comp_except_specs (new_exceptions, old_exceptions, ce_normal))
    {
      const char *const msg
	= G_("declaration of %qF has a different exception specifier");
      bool complained = true;
      location_t new_loc = DECL_SOURCE_LOCATION (new_decl);
      auto_diagnostic_group d;
      if (DECL_IN_SYSTEM_HEADER (old_decl))
	complained = pedwarn (new_loc, OPT_Wsystem_headers, msg, new_decl);
      else if (!flag_exceptions)
	/* We used to silently permit mismatched eh specs with
	   -fno-exceptions, so make them a pedwarn now.  */
	complained = pedwarn (new_loc, OPT_Wpedantic, msg, new_decl);
      else
	error_at (new_loc, msg, new_decl);
      if (complained)
	inform (DECL_SOURCE_LOCATION (old_decl),
		"from previous declaration %qF", old_decl);
    }
}

/* Return true if OLD_DECL and NEW_DECL agree on constexprness.
   Otherwise issue diagnostics.  */

static bool
validate_constexpr_redeclaration (tree old_decl, tree new_decl)
{
  old_decl = STRIP_TEMPLATE (old_decl);
  new_decl = STRIP_TEMPLATE (new_decl);
  if (!VAR_OR_FUNCTION_DECL_P (old_decl)
      || !VAR_OR_FUNCTION_DECL_P (new_decl))
    return true;
  if (DECL_DECLARED_CONSTEXPR_P (old_decl)
      == DECL_DECLARED_CONSTEXPR_P (new_decl))
    {
      if (TREE_CODE (old_decl) != FUNCTION_DECL)
	return true;
      if (DECL_IMMEDIATE_FUNCTION_P (old_decl)
	  == DECL_IMMEDIATE_FUNCTION_P (new_decl))
	return true;
    }
  if (TREE_CODE (old_decl) == FUNCTION_DECL)
    {
      /* With -fimplicit-constexpr, ignore changes in the constexpr
	 keyword.  */
      if (flag_implicit_constexpr
	  && (DECL_IMMEDIATE_FUNCTION_P (new_decl)
	      == DECL_IMMEDIATE_FUNCTION_P (old_decl)))
	return true;
      if (fndecl_built_in_p (old_decl))
	{
	  /* Hide a built-in declaration.  */
	  DECL_DECLARED_CONSTEXPR_P (old_decl)
	    = DECL_DECLARED_CONSTEXPR_P (new_decl);
	  if (DECL_IMMEDIATE_FUNCTION_P (new_decl))
	    SET_DECL_IMMEDIATE_FUNCTION_P (old_decl);
	  return true;
	}
      /* 7.1.5 [dcl.constexpr]
	 Note: An explicit specialization can differ from the template
	 declaration with respect to the constexpr specifier.  */
      if (! DECL_TEMPLATE_SPECIALIZATION (old_decl)
	  && DECL_TEMPLATE_SPECIALIZATION (new_decl))
	return true;

      const char *kind = "constexpr";
      if (DECL_IMMEDIATE_FUNCTION_P (old_decl)
	  || DECL_IMMEDIATE_FUNCTION_P (new_decl))
	kind = "consteval";
      error_at (DECL_SOURCE_LOCATION (new_decl),
		"redeclaration %qD differs in %qs "
		"from previous declaration", new_decl,
		kind);
      inform (DECL_SOURCE_LOCATION (old_decl),
	      "previous declaration %qD", old_decl);
      return false;
    }
  return true;
}

// If OLDDECL and NEWDECL are concept declarations with the same type
// (i.e., and template parameters), but different requirements,
// emit diagnostics and return true. Otherwise, return false.
static inline bool
check_concept_refinement (tree olddecl, tree newdecl)
{
  if (!DECL_DECLARED_CONCEPT_P (olddecl) || !DECL_DECLARED_CONCEPT_P (newdecl))
    return false;

  tree d1 = DECL_TEMPLATE_RESULT (olddecl);
  tree d2 = DECL_TEMPLATE_RESULT (newdecl);
  if (TREE_CODE (d1) != TREE_CODE (d2))
    return false;

  tree t1 = TREE_TYPE (d1);
  tree t2 = TREE_TYPE (d2);
  if (TREE_CODE (d1) == FUNCTION_DECL)
    {
      if (compparms (TYPE_ARG_TYPES (t1), TYPE_ARG_TYPES (t2))
          && comp_template_parms (DECL_TEMPLATE_PARMS (olddecl),
                                  DECL_TEMPLATE_PARMS (newdecl))
          && !equivalently_constrained (olddecl, newdecl))
        {
          error ("cannot specialize concept %q#D", olddecl);
          return true;
        }
    }
  return false;
}

/* DECL is a redeclaration of a function or function template.  If
   it does have default arguments issue a diagnostic.  Note: this
   function is used to enforce the requirements in C++11 8.3.6 about
   no default arguments in redeclarations.  */

static void
check_redeclaration_no_default_args (tree decl)
{
  gcc_assert (DECL_DECLARES_FUNCTION_P (decl));

  for (tree t = FUNCTION_FIRST_USER_PARMTYPE (decl);
       t && t != void_list_node; t = TREE_CHAIN (t))
    if (TREE_PURPOSE (t))
      {
	permerror (DECL_SOURCE_LOCATION (decl),
		   "redeclaration of %q#D may not have default "
		   "arguments", decl);
	return;
      }
}

/* NEWDECL is a redeclaration of a function or function template OLDDECL,
   in any case represented as FUNCTION_DECLs (the DECL_TEMPLATE_RESULTs of
   the TEMPLATE_DECLs in case of function templates).  This function is used
   to enforce the final part of C++17 11.3.6/4, about a single declaration:
   "If a friend declaration specifies a default argument expression, that
   declaration shall be a definition and shall be the only declaration of
   the function or function template in the translation unit."  */

static void
check_no_redeclaration_friend_default_args (tree olddecl, tree newdecl)
{
  if (!DECL_UNIQUE_FRIEND_P (olddecl) && !DECL_UNIQUE_FRIEND_P (newdecl))
    return;

  for (tree t1 = FUNCTION_FIRST_USER_PARMTYPE (olddecl),
	 t2 = FUNCTION_FIRST_USER_PARMTYPE (newdecl);
       t1 && t1 != void_list_node;
       t1 = TREE_CHAIN (t1), t2 = TREE_CHAIN (t2))
    if ((DECL_UNIQUE_FRIEND_P (olddecl) && TREE_PURPOSE (t1))
	|| (DECL_UNIQUE_FRIEND_P (newdecl) && TREE_PURPOSE (t2)))
      {
	auto_diagnostic_group d;
	if (permerror (DECL_SOURCE_LOCATION (newdecl),
		       "friend declaration of %q#D specifies default "
		       "arguments and isn%'t the only declaration", newdecl))
	  inform (DECL_SOURCE_LOCATION (olddecl),
		  "previous declaration of %q#D", olddecl);
	return;
      }
}

/* Merge tree bits that correspond to attributes noreturn, nothrow,
   const,  malloc, and pure from NEWDECL with those of OLDDECL.  */

static void
merge_attribute_bits (tree newdecl, tree olddecl)
{
  TREE_THIS_VOLATILE (newdecl) |= TREE_THIS_VOLATILE (olddecl);
  TREE_THIS_VOLATILE (olddecl) |= TREE_THIS_VOLATILE (newdecl);
  TREE_NOTHROW (newdecl) |= TREE_NOTHROW (olddecl);
  TREE_NOTHROW (olddecl) |= TREE_NOTHROW (newdecl);
  TREE_READONLY (newdecl) |= TREE_READONLY (olddecl);
  TREE_READONLY (olddecl) |= TREE_READONLY (newdecl);
  DECL_IS_MALLOC (newdecl) |= DECL_IS_MALLOC (olddecl);
  DECL_IS_MALLOC (olddecl) |= DECL_IS_MALLOC (newdecl);
  DECL_PURE_P (newdecl) |= DECL_PURE_P (olddecl);
  DECL_PURE_P (olddecl) |= DECL_PURE_P (newdecl);
  DECL_UNINLINABLE (newdecl) |= DECL_UNINLINABLE (olddecl);
  DECL_UNINLINABLE (olddecl) |= DECL_UNINLINABLE (newdecl);
}

#define GNU_INLINE_P(fn) (DECL_DECLARED_INLINE_P (fn)			\
			  && lookup_attribute ("gnu_inline",		\
					       DECL_ATTRIBUTES (fn)))

/* A subroutine of duplicate_decls. Emits a diagnostic when newdecl
   ambiguates olddecl.  Returns true if an error occurs.  */

static bool
duplicate_function_template_decls (tree newdecl, tree olddecl)
{

  tree newres = DECL_TEMPLATE_RESULT (newdecl);
  tree oldres = DECL_TEMPLATE_RESULT (olddecl);
  /* Function template declarations can be differentiated by parameter
     and return type.  */
  if (compparms (TYPE_ARG_TYPES (TREE_TYPE (oldres)),
		 TYPE_ARG_TYPES (TREE_TYPE (newres)))
       && same_type_p (TREE_TYPE (TREE_TYPE (newdecl)),
		       TREE_TYPE (TREE_TYPE (olddecl))))
    {
      /* ... and also by their template-heads and requires-clauses.  */
      if (template_heads_equivalent_p (newdecl, olddecl)
	  && function_requirements_equivalent_p (newres, oldres))
	{
	  error ("ambiguating new declaration %q+#D", newdecl);
	  inform (DECL_SOURCE_LOCATION (olddecl),
		  "old declaration %q#D", olddecl);
	  return true;
	}

      /* FIXME: The types are the same but the are differences
	 in either the template heads or function requirements.
	 We should be able to diagnose a set of common errors
	 stemming from these declarations. For example:

	   template<typename T> requires C void f(...);
	   template<typename T> void f(...) requires C;

	 These are functionally equivalent but not equivalent.  */
    }

  return false;
}

/* OLD_PARMS is the innermost set of template parameters for some template
   declaration, and NEW_PARMS is the corresponding set of template parameters
   for a redeclaration of that template.  Merge the default arguments within
   these two sets of parameters.  CLASS_P is true iff the template in
   question is a class template.  */

bool
merge_default_template_args (tree new_parms, tree old_parms, bool class_p)
{
  gcc_checking_assert (TREE_VEC_LENGTH (new_parms)
		       == TREE_VEC_LENGTH (old_parms));
  for (int i = 0; i < TREE_VEC_LENGTH (new_parms); i++)
    {
      tree new_parm = TREE_VALUE (TREE_VEC_ELT (new_parms, i));
      tree old_parm = TREE_VALUE (TREE_VEC_ELT (old_parms, i));
      tree& new_default = TREE_PURPOSE (TREE_VEC_ELT (new_parms, i));
      tree& old_default = TREE_PURPOSE (TREE_VEC_ELT (old_parms, i));
      if (error_operand_p (new_parm) || error_operand_p (old_parm))
	return false;
      if (new_default != NULL_TREE && old_default != NULL_TREE)
	{
	  auto_diagnostic_group d;
	  error ("redefinition of default argument for %q+#D", new_parm);
	  inform (DECL_SOURCE_LOCATION (old_parm),
		  "original definition appeared here");
	  return false;
	}
      else if (new_default != NULL_TREE)
	/* Update the previous template parameters (which are the ones
	   that will really count) with the new default value.  */
	old_default = new_default;
      else if (class_p && old_default != NULL_TREE)
	/* Update the new parameters, too; they'll be used as the
	   parameters for any members.  */
	new_default = old_default;
    }
  return true;
}

/* If NEWDECL is a redeclaration of OLDDECL, merge the declarations.
   If the redeclaration is invalid, a diagnostic is issued, and the
   error_mark_node is returned.  Otherwise, OLDDECL is returned.

   If NEWDECL is not a redeclaration of OLDDECL, NULL_TREE is
   returned.

   HIDING is true if the new decl is being hidden.  WAS_HIDDEN is true
   if the old decl was hidden.

   Hidden decls can be anticipated builtins, injected friends, or
   (coming soon) injected from a local-extern decl.   */

tree
duplicate_decls (tree newdecl, tree olddecl, bool hiding, bool was_hidden)
{
  unsigned olddecl_uid = DECL_UID (olddecl);
  int types_match = 0;
  int new_defines_function = 0;
  tree new_template_info;
  location_t olddecl_loc = DECL_SOURCE_LOCATION (olddecl);
  location_t newdecl_loc = DECL_SOURCE_LOCATION (newdecl);

  if (newdecl == olddecl)
    return olddecl;

  types_match = decls_match (newdecl, olddecl);

  /* If either the type of the new decl or the type of the old decl is an
     error_mark_node, then that implies that we have already issued an
     error (earlier) for some bogus type specification, and in that case,
     it is rather pointless to harass the user with yet more error message
     about the same declaration, so just pretend the types match here.  */
  if (TREE_TYPE (newdecl) == error_mark_node
      || TREE_TYPE (olddecl) == error_mark_node)
    return error_mark_node;

  /* Check for redeclaration and other discrepancies.  */
  if (TREE_CODE (olddecl) == FUNCTION_DECL
      && DECL_IS_UNDECLARED_BUILTIN (olddecl))
    {
      if (TREE_CODE (newdecl) != FUNCTION_DECL)
	{
	  /* Avoid warnings redeclaring built-ins which have not been
	     explicitly declared.  */
	  if (was_hidden)
	    {
	      if (TREE_PUBLIC (newdecl)
		  && CP_DECL_CONTEXT (newdecl) == global_namespace)
		warning_at (newdecl_loc,
			    OPT_Wbuiltin_declaration_mismatch,
			    "built-in function %qD declared as non-function",
			    newdecl);
	      return NULL_TREE;
	    }

	  /* If you declare a built-in or predefined function name as static,
	     the old definition is overridden, but optionally warn this was a
	     bad choice of name.  */
	  if (! TREE_PUBLIC (newdecl))
	    {
	      warning_at (newdecl_loc,
			  OPT_Wshadow, 
			  fndecl_built_in_p (olddecl)
			  ? G_("shadowing built-in function %q#D")
			  : G_("shadowing library function %q#D"), olddecl);
	      /* Discard the old built-in function.  */
	      return NULL_TREE;
	    }
	  /* If the built-in is not ansi, then programs can override
	     it even globally without an error.  */
	  else if (! fndecl_built_in_p (olddecl))
	    warning_at (newdecl_loc, 0,
			"library function %q#D redeclared as non-function %q#D",
			olddecl, newdecl);
	  else
	    error_at (newdecl_loc,
		      "declaration of %q#D conflicts with built-in "
		      "declaration %q#D", newdecl, olddecl);
	  return NULL_TREE;
	}
      else if (!types_match)
	{
	  /* Avoid warnings redeclaring built-ins which have not been
	     explicitly declared.  */
	  if (was_hidden)
	    {
	      tree t1, t2;

	      /* A new declaration doesn't match a built-in one unless it
		 is also extern "C".  */
	      gcc_assert (DECL_IS_UNDECLARED_BUILTIN (olddecl));
	      gcc_assert (DECL_EXTERN_C_P (olddecl));
	      if (!DECL_EXTERN_C_P (newdecl))
		return NULL_TREE;

	      for (t1 = TYPE_ARG_TYPES (TREE_TYPE (newdecl)),
		   t2 = TYPE_ARG_TYPES (TREE_TYPE (olddecl));
		   t1 || t2;
		   t1 = TREE_CHAIN (t1), t2 = TREE_CHAIN (t2))
		{
		  if (!t1 || !t2)
		    break;
		  /* FILE, tm types are not known at the time
		     we create the builtins.  */
		  for (unsigned i = 0;
		       i < sizeof (builtin_structptr_types)
			   / sizeof (builtin_structptr_type);
		       ++i)
		    if (TREE_VALUE (t2) == builtin_structptr_types[i].node)
		      {
			tree t = TREE_VALUE (t1);

			if (TYPE_PTR_P (t)
			    && TYPE_IDENTIFIER (TREE_TYPE (t))
			    == get_identifier (builtin_structptr_types[i].str)
			    && compparms (TREE_CHAIN (t1), TREE_CHAIN (t2)))
			  {
			    tree oldargs = TYPE_ARG_TYPES (TREE_TYPE (olddecl));

			    TYPE_ARG_TYPES (TREE_TYPE (olddecl))
			      = TYPE_ARG_TYPES (TREE_TYPE (newdecl));
			    types_match = decls_match (newdecl, olddecl);
			    if (types_match)
			      return duplicate_decls (newdecl, olddecl,
						      hiding, was_hidden);
			    TYPE_ARG_TYPES (TREE_TYPE (olddecl)) = oldargs;
			  }
			goto next_arg;
		      }

		  if (! same_type_p (TREE_VALUE (t1), TREE_VALUE (t2)))
		    break;
		next_arg:;
		}

	      warning_at (newdecl_loc,
			  OPT_Wbuiltin_declaration_mismatch,
			  "declaration of %q#D conflicts with built-in "
			  "declaration %q#D", newdecl, olddecl);
	    }
	  else if ((DECL_EXTERN_C_P (newdecl)
		    && DECL_EXTERN_C_P (olddecl))
		   || compparms (TYPE_ARG_TYPES (TREE_TYPE (newdecl)),
				 TYPE_ARG_TYPES (TREE_TYPE (olddecl))))
	    {
	      /* Don't really override olddecl for __* prefixed builtins
		 except for __[^b]*_chk, the compiler might be using those
		 explicitly.  */
	      if (fndecl_built_in_p (olddecl))
		{
		  tree id = DECL_NAME (olddecl);
		  const char *name = IDENTIFIER_POINTER (id);
		  size_t len;

		  if (name[0] == '_'
		      && name[1] == '_'
		      && (startswith (name + 2, "builtin_")
			  || (len = strlen (name)) <= strlen ("___chk")
			  || memcmp (name + len - strlen ("_chk"),
				     "_chk", strlen ("_chk") + 1) != 0))
		    {
		      if (DECL_INITIAL (newdecl))
			{
			  error_at (newdecl_loc,
				    "definition of %q#D ambiguates built-in "
				    "declaration %q#D", newdecl, olddecl);
			  return error_mark_node;
			}
		      auto_diagnostic_group d;
		      if (permerror (newdecl_loc,
				     "new declaration %q#D ambiguates built-in"
				     " declaration %q#D", newdecl, olddecl)
			  && flag_permissive)
			inform (newdecl_loc,
				"ignoring the %q#D declaration", newdecl);
		      return flag_permissive ? olddecl : error_mark_node;
		    }
		}

	      /* A near match; override the builtin.  */

	      if (TREE_PUBLIC (newdecl))
		warning_at (newdecl_loc,
			    OPT_Wbuiltin_declaration_mismatch,
			    "new declaration %q#D ambiguates built-in "
			    "declaration %q#D", newdecl, olddecl);
	      else
		warning (OPT_Wshadow, 
			 fndecl_built_in_p (olddecl)
			 ? G_("shadowing built-in function %q#D")
			 : G_("shadowing library function %q#D"), olddecl);
	    }
	  else
	    /* Discard the old built-in function.  */
	    return NULL_TREE;

	  /* Replace the old RTL to avoid problems with inlining.  */
	  COPY_DECL_RTL (newdecl, olddecl);
	}
      else 
	{
	  /* Even if the types match, prefer the new declarations type
	     for built-ins which have not been explicitly declared,
	     for exception lists, etc...  */
	  tree type = TREE_TYPE (newdecl);
	  tree attribs = (*targetm.merge_type_attributes)
	    (TREE_TYPE (olddecl), type);

	  type = cp_build_type_attribute_variant (type, attribs);
	  TREE_TYPE (newdecl) = TREE_TYPE (olddecl) = type;
	}

      /* If a function is explicitly declared "throw ()", propagate that to
	 the corresponding builtin.  */
      if (DECL_BUILT_IN_CLASS (olddecl) == BUILT_IN_NORMAL
	  && was_hidden
	  && TREE_NOTHROW (newdecl)
	  && !TREE_NOTHROW (olddecl))
	{
	  enum built_in_function fncode = DECL_FUNCTION_CODE (olddecl);
	  tree tmpdecl = builtin_decl_explicit (fncode);
	  if (tmpdecl && tmpdecl != olddecl && types_match)
	    TREE_NOTHROW (tmpdecl)  = 1;
	}

      /* Whether or not the builtin can throw exceptions has no
	 bearing on this declarator.  */
      TREE_NOTHROW (olddecl) = 0;

      if (DECL_THIS_STATIC (newdecl) && !DECL_THIS_STATIC (olddecl))
	{
	  /* If a builtin function is redeclared as `static', merge
	     the declarations, but make the original one static.  */
	  DECL_THIS_STATIC (olddecl) = 1;
	  TREE_PUBLIC (olddecl) = 0;

	  /* Make the old declaration consistent with the new one so
	     that all remnants of the builtin-ness of this function
	     will be banished.  */
	  SET_DECL_LANGUAGE (olddecl, DECL_LANGUAGE (newdecl));
	  COPY_DECL_RTL (newdecl, olddecl);
	}
    }
  else if (TREE_CODE (olddecl) != TREE_CODE (newdecl))
    {
      /* C++ Standard, 3.3, clause 4:
	 "[Note: a namespace name or a class template name must be unique
	 in its declarative region (7.3.2, clause 14). ]"  */
      if (TREE_CODE (olddecl) == NAMESPACE_DECL
	  || TREE_CODE (newdecl) == NAMESPACE_DECL)
	/* Namespace conflicts with not namespace.  */;
      else if (DECL_TYPE_TEMPLATE_P (olddecl)
	       || DECL_TYPE_TEMPLATE_P (newdecl))
	/* Class template conflicts.  */;
      else if ((TREE_CODE (olddecl) == TEMPLATE_DECL
		&& DECL_TEMPLATE_RESULT (olddecl)
		&& TREE_CODE (DECL_TEMPLATE_RESULT (olddecl)) == VAR_DECL)
	       || (TREE_CODE (newdecl) == TEMPLATE_DECL
		   && DECL_TEMPLATE_RESULT (newdecl)
		   && TREE_CODE (DECL_TEMPLATE_RESULT (newdecl)) == VAR_DECL))
	/* Variable template conflicts.  */;
      else if (concept_definition_p (olddecl)
	       || concept_definition_p (newdecl))
	/* Concept conflicts.  */;
      else if ((TREE_CODE (newdecl) == FUNCTION_DECL
		&& DECL_FUNCTION_TEMPLATE_P (olddecl))
	       || (TREE_CODE (olddecl) == FUNCTION_DECL
		   && DECL_FUNCTION_TEMPLATE_P (newdecl)))
	{
	  /* One is a function and the other is a template
	     function.  */
	  if (!UDLIT_OPER_P (DECL_NAME (newdecl)))
	    return NULL_TREE;

	  /* There can only be one!  */
	  if (TREE_CODE (newdecl) == TEMPLATE_DECL
	      && check_raw_literal_operator (olddecl))
	    error_at (newdecl_loc,
		      "literal operator %q#D conflicts with"
		      " raw literal operator", newdecl);
	  else if (check_raw_literal_operator (newdecl))
	    error_at (newdecl_loc,
		      "raw literal operator %q#D conflicts with"
		      " literal operator template", newdecl);
	  else
	    return NULL_TREE;

	  inform (olddecl_loc, "previous declaration %q#D", olddecl);
	  return error_mark_node;
	}
      else if ((VAR_P (olddecl) && DECL_DECOMPOSITION_P (olddecl))
	       || (VAR_P (newdecl) && DECL_DECOMPOSITION_P (newdecl)))
	/* A structured binding must be unique in its declarative region.  */;
      else if (DECL_IMPLICIT_TYPEDEF_P (olddecl)
	       || DECL_IMPLICIT_TYPEDEF_P (newdecl))
	/* One is an implicit typedef, that's ok.  */
	return NULL_TREE;

      error ("%q#D redeclared as different kind of entity", newdecl);
      inform (olddecl_loc, "previous declaration %q#D", olddecl);

      return error_mark_node;
    }
  else if (!types_match)
    {
      if (CP_DECL_CONTEXT (newdecl) != CP_DECL_CONTEXT (olddecl))
	/* These are certainly not duplicate declarations; they're
	   from different scopes.  */
	return NULL_TREE;

      if (TREE_CODE (newdecl) == TEMPLATE_DECL)
	{
	  tree oldres = DECL_TEMPLATE_RESULT (olddecl);
	  tree newres = DECL_TEMPLATE_RESULT (newdecl);

	  /* The name of a class template may not be declared to refer to
	     any other template, class, function, object, namespace, value,
	     or type in the same scope.  */
	  if (TREE_CODE (oldres) == TYPE_DECL
	      || TREE_CODE (newres) == TYPE_DECL)
	    {
	      error_at (newdecl_loc,
			"conflicting declaration of template %q#D", newdecl);
	      inform (olddecl_loc,
		      "previous declaration %q#D", olddecl);
	      return error_mark_node;
	    }

	  else if (TREE_CODE (oldres) == FUNCTION_DECL
		   && TREE_CODE (newres) == FUNCTION_DECL)
	    {
	      if (duplicate_function_template_decls (newdecl, olddecl))
		return error_mark_node;
	      return NULL_TREE;
	    }
          else if (check_concept_refinement (olddecl, newdecl))
	    return error_mark_node;
	  return NULL_TREE;
	}
      if (TREE_CODE (newdecl) == FUNCTION_DECL)
	{
	  if (DECL_EXTERN_C_P (newdecl) && DECL_EXTERN_C_P (olddecl))
	    {
	      error_at (newdecl_loc,
			"conflicting declaration of C function %q#D",
			newdecl);
	      inform (olddecl_loc,
		      "previous declaration %q#D", olddecl);
	      return error_mark_node;
	    }
	  /* For function versions, params and types match, but they
	     are not ambiguous.  */
	  else if ((!DECL_FUNCTION_VERSIONED (newdecl)
		    && !DECL_FUNCTION_VERSIONED (olddecl))
                   // The functions have the same parameter types.
		   && compparms (TYPE_ARG_TYPES (TREE_TYPE (newdecl)),
				 TYPE_ARG_TYPES (TREE_TYPE (olddecl)))
                   // And the same constraints.
                   && equivalently_constrained (newdecl, olddecl))
	    {
	      error_at (newdecl_loc,
			"ambiguating new declaration of %q#D", newdecl);
	      inform (olddecl_loc,
		      "old declaration %q#D", olddecl);
              return error_mark_node;
	    }
	  else
	    return NULL_TREE;
	}
      else
	{
	  error_at (newdecl_loc, "conflicting declaration %q#D", newdecl);
	  inform (olddecl_loc,
		  "previous declaration as %q#D", olddecl);
	  return error_mark_node;
	}
    }
  else if (TREE_CODE (newdecl) == FUNCTION_DECL
	   && DECL_OMP_DECLARE_REDUCTION_P (newdecl))
    {
      /* OMP UDRs are never duplicates. */
      gcc_assert (DECL_OMP_DECLARE_REDUCTION_P (olddecl));
      error_at (newdecl_loc,
		"redeclaration of %<pragma omp declare reduction%>");
      inform (olddecl_loc,
	      "previous %<pragma omp declare reduction%> declaration");
      return error_mark_node;
    }
  else if (TREE_CODE (newdecl) == FUNCTION_DECL
	    && ((DECL_TEMPLATE_SPECIALIZATION (olddecl)
		 && (!DECL_TEMPLATE_INFO (newdecl)
		     || (DECL_TI_TEMPLATE (newdecl)
			 != DECL_TI_TEMPLATE (olddecl))))
		|| (DECL_TEMPLATE_SPECIALIZATION (newdecl)
		    && (!DECL_TEMPLATE_INFO (olddecl)
			|| (DECL_TI_TEMPLATE (olddecl)
			    != DECL_TI_TEMPLATE (newdecl))))))
    /* It's OK to have a template specialization and a non-template
       with the same type, or to have specializations of two
       different templates with the same type.  Note that if one is a
       specialization, and the other is an instantiation of the same
       template, that we do not exit at this point.  That situation
       can occur if we instantiate a template class, and then
       specialize one of its methods.  This situation is valid, but
       the declarations must be merged in the usual way.  */
    return NULL_TREE;
  else if (TREE_CODE (newdecl) == FUNCTION_DECL
	   && ((DECL_TEMPLATE_INSTANTIATION (olddecl)
		&& !DECL_USE_TEMPLATE (newdecl))
	       || (DECL_TEMPLATE_INSTANTIATION (newdecl)
		   && !DECL_USE_TEMPLATE (olddecl))))
    /* One of the declarations is a template instantiation, and the
       other is not a template at all.  That's OK.  */
    return NULL_TREE;
  else if (TREE_CODE (newdecl) == NAMESPACE_DECL)
    {
      /* In [namespace.alias] we have:

	   In a declarative region, a namespace-alias-definition can be
	   used to redefine a namespace-alias declared in that declarative
	   region to refer only to the namespace to which it already
	   refers.

	 Therefore, if we encounter a second alias directive for the same
	 alias, we can just ignore the second directive.  */
      if (DECL_NAMESPACE_ALIAS (newdecl)
	  && (DECL_NAMESPACE_ALIAS (newdecl)
	      == DECL_NAMESPACE_ALIAS (olddecl)))
	return olddecl;

      /* Leave it to update_binding to merge or report error.  */
      return NULL_TREE;
    }
  else
    {
      const char *errmsg = redeclaration_error_message (newdecl, olddecl);
      if (errmsg)
	{
	  auto_diagnostic_group d;
	  error_at (newdecl_loc, errmsg, newdecl);
	  if (DECL_NAME (olddecl) != NULL_TREE)
	    inform (olddecl_loc,
		    (DECL_INITIAL (olddecl) && namespace_bindings_p ())
		    ? G_("%q#D previously defined here")
		    : G_("%q#D previously declared here"), olddecl);
	  return error_mark_node;
	}
      else if (TREE_CODE (olddecl) == FUNCTION_DECL
	       && DECL_INITIAL (olddecl) != NULL_TREE
	       && !prototype_p (TREE_TYPE (olddecl))
	       && prototype_p (TREE_TYPE (newdecl)))
	{
	  /* Prototype decl follows defn w/o prototype.  */
	  auto_diagnostic_group d;
	  if (warning_at (newdecl_loc, 0,
			  "prototype specified for %q#D", newdecl))
	    inform (olddecl_loc,
		    "previous non-prototype definition here");
	}
      else if (VAR_OR_FUNCTION_DECL_P (olddecl)
	       && DECL_LANGUAGE (newdecl) != DECL_LANGUAGE (olddecl))
	{
	  /* [dcl.link]
	     If two declarations of the same function or object
	     specify different linkage-specifications ..., the program
	     is ill-formed.... Except for functions with C++ linkage,
	     a function declaration without a linkage specification
	     shall not precede the first linkage specification for
	     that function.  A function can be declared without a
	     linkage specification after an explicit linkage
	     specification has been seen; the linkage explicitly
	     specified in the earlier declaration is not affected by
	     such a function declaration.

	     DR 563 raises the question why the restrictions on
	     functions should not also apply to objects.  Older
	     versions of G++ silently ignore the linkage-specification
	     for this example:

	       namespace N { 
                 extern int i;
   	         extern "C" int i;
               }

             which is clearly wrong.  Therefore, we now treat objects
	     like functions.  */
	  if (current_lang_depth () == 0)
	    {
	      /* There is no explicit linkage-specification, so we use
		 the linkage from the previous declaration.  */
	      retrofit_lang_decl (newdecl);
	      SET_DECL_LANGUAGE (newdecl, DECL_LANGUAGE (olddecl));
	    }
	  else
	    {
	      auto_diagnostic_group d;
	      error_at (newdecl_loc,
			"conflicting declaration of %q#D with %qL linkage",
			newdecl, DECL_LANGUAGE (newdecl));
	      inform (olddecl_loc,
		      "previous declaration with %qL linkage",
		      DECL_LANGUAGE (olddecl));
	    }
	}

      if (DECL_LANG_SPECIFIC (olddecl) && DECL_USE_TEMPLATE (olddecl))
	;
      else if (TREE_CODE (olddecl) == FUNCTION_DECL)
	{
	  /* Note: free functions, as TEMPLATE_DECLs, are handled below.  */
	  if (DECL_FUNCTION_MEMBER_P (olddecl)
	      && (/* grokfndecl passes member function templates too
		     as FUNCTION_DECLs.  */
		  DECL_TEMPLATE_INFO (olddecl)
		  /* C++11 8.3.6/6.
		     Default arguments for a member function of a class
		     template shall be specified on the initial declaration
		     of the member function within the class template.  */
		  || CLASSTYPE_TEMPLATE_INFO (CP_DECL_CONTEXT (olddecl))))
	    {
	      check_redeclaration_no_default_args (newdecl);

	      if (DECL_TEMPLATE_INFO (olddecl)
		  && DECL_MEMBER_TEMPLATE_P (DECL_TI_TEMPLATE (olddecl)))
		{
		  tree new_parms = DECL_TEMPLATE_INFO (newdecl)
		    ? DECL_INNERMOST_TEMPLATE_PARMS (DECL_TI_TEMPLATE (newdecl))
		    : INNERMOST_TEMPLATE_PARMS (current_template_parms);
		  tree old_parms
		    = DECL_INNERMOST_TEMPLATE_PARMS (DECL_TI_TEMPLATE (olddecl));
		  merge_default_template_args (new_parms, old_parms,
					       /*class_p=*/false);
		}
	    }
	  else
	    {
	      tree t1 = FUNCTION_FIRST_USER_PARMTYPE (olddecl);
	      tree t2 = FUNCTION_FIRST_USER_PARMTYPE (newdecl);
	      int i = 1;

	      for (; t1 && t1 != void_list_node;
		   t1 = TREE_CHAIN (t1), t2 = TREE_CHAIN (t2), i++)
		if (TREE_PURPOSE (t1) && TREE_PURPOSE (t2))
		  {
		    if (simple_cst_equal (TREE_PURPOSE (t1),
					  TREE_PURPOSE (t2)) == 1)
		      {
			auto_diagnostic_group d;
			if (permerror (newdecl_loc,
				       "default argument given for parameter "
				       "%d of %q#D", i, newdecl))
			  inform (olddecl_loc,
				  "previous specification in %q#D here",
				  olddecl);
		      }
		    else
		      {
			auto_diagnostic_group d;
			error_at (newdecl_loc,
				  "default argument given for parameter %d "
				  "of %q#D", i, newdecl);
			inform (olddecl_loc,
				"previous specification in %q#D here",
				olddecl);
		      }
		  }

	      /* C++17 11.3.6/4: "If a friend declaration specifies a default
		 argument expression, that declaration... shall be the only
		 declaration of the function or function template in the
		 translation unit."  */
	      check_no_redeclaration_friend_default_args (olddecl, newdecl);
	    }
	}
    }

  /* Do not merge an implicit typedef with an explicit one.  In:

       class A;
       ...
       typedef class A A __attribute__ ((foo));

     the attribute should apply only to the typedef.  */
  if (TREE_CODE (olddecl) == TYPE_DECL
      && (DECL_IMPLICIT_TYPEDEF_P (olddecl)
	  || DECL_IMPLICIT_TYPEDEF_P (newdecl)))
    return NULL_TREE;

  if (DECL_TEMPLATE_PARM_P (olddecl) != DECL_TEMPLATE_PARM_P (newdecl))
    return NULL_TREE;

  if (!validate_constexpr_redeclaration (olddecl, newdecl))
    return error_mark_node;

  if (modules_p ()
      && TREE_CODE (CP_DECL_CONTEXT (olddecl)) == NAMESPACE_DECL
      && TREE_CODE (olddecl) != NAMESPACE_DECL
      && !hiding)
    {
      if (DECL_ARTIFICIAL (olddecl))
	{
	  if (!(global_purview_p () || not_module_p ()))
	    error ("declaration %qD conflicts with builtin", newdecl);
	  else
	    DECL_MODULE_EXPORT_P (olddecl) = DECL_MODULE_EXPORT_P (newdecl);
	}
      else
	{
	  if (!module_may_redeclare (olddecl))
	    {
	      error ("declaration %qD conflicts with import", newdecl);
	      inform (olddecl_loc, "import declared %q#D here", olddecl);

	      return error_mark_node;
	    }

	  if (DECL_MODULE_EXPORT_P (newdecl)
	      && !DECL_MODULE_EXPORT_P (olddecl))
	    {
	      error ("conflicting exporting declaration %qD", newdecl);
	      inform (olddecl_loc, "previous declaration %q#D here", olddecl);
	    }
	}
    }

  /* We have committed to returning OLDDECL at this point.  */

  /* If new decl is `static' and an `extern' was seen previously,
     warn about it.  */
  warn_extern_redeclared_static (newdecl, olddecl);

  /* True to merge attributes between the declarations, false to
     set OLDDECL's attributes to those of NEWDECL (for template
     explicit specializations that specify their own attributes
     independent of those specified for the primary template).  */
  const bool merge_attr = (TREE_CODE (newdecl) != FUNCTION_DECL
			   || !DECL_TEMPLATE_SPECIALIZATION (newdecl)
			   || DECL_TEMPLATE_SPECIALIZATION (olddecl));

  if (TREE_CODE (newdecl) == FUNCTION_DECL)
    {
      if (merge_attr)
	{
	  if (diagnose_mismatched_attributes (olddecl, newdecl))
	    inform (olddecl_loc, DECL_INITIAL (olddecl)
		    ? G_("previous definition of %qD here")
		    : G_("previous declaration of %qD here"), olddecl);

	  /* [dcl.attr.noreturn]: The first declaration of a function shall
	     specify the noreturn attribute if any declaration of that function
	     specifies the noreturn attribute.  */
	  tree a;
	  if (TREE_THIS_VOLATILE (newdecl)
	      && !TREE_THIS_VOLATILE (olddecl)
	      /* This applies to [[noreturn]] only, not its GNU variants.  */
	      && (a = lookup_attribute ("noreturn", DECL_ATTRIBUTES (newdecl)))
	      && cxx11_attribute_p (a)
	      && get_attribute_namespace (a) == NULL_TREE)
	    {
	      error_at (newdecl_loc, "function %qD declared %<[[noreturn]]%> "
			"but its first declaration was not", newdecl);
	      inform (olddecl_loc, "previous declaration of %qD", olddecl);
	    }
	}

      /* Now that functions must hold information normally held
	 by field decls, there is extra work to do so that
	 declaration information does not get destroyed during
	 definition.  */
      if (DECL_VINDEX (olddecl))
	DECL_VINDEX (newdecl) = DECL_VINDEX (olddecl);
      if (DECL_CONTEXT (olddecl))
	DECL_CONTEXT (newdecl) = DECL_CONTEXT (olddecl);
      DECL_STATIC_CONSTRUCTOR (newdecl) |= DECL_STATIC_CONSTRUCTOR (olddecl);
      DECL_STATIC_DESTRUCTOR (newdecl) |= DECL_STATIC_DESTRUCTOR (olddecl);
      DECL_PURE_VIRTUAL_P (newdecl) |= DECL_PURE_VIRTUAL_P (olddecl);
      DECL_VIRTUAL_P (newdecl) |= DECL_VIRTUAL_P (olddecl);
      DECL_INVALID_OVERRIDER_P (newdecl) |= DECL_INVALID_OVERRIDER_P (olddecl);
      DECL_FINAL_P (newdecl) |= DECL_FINAL_P (olddecl);
      DECL_OVERRIDE_P (newdecl) |= DECL_OVERRIDE_P (olddecl);
      DECL_THIS_STATIC (newdecl) |= DECL_THIS_STATIC (olddecl);
      DECL_HAS_DEPENDENT_EXPLICIT_SPEC_P (newdecl)
	|= DECL_HAS_DEPENDENT_EXPLICIT_SPEC_P (olddecl);
      if (DECL_OVERLOADED_OPERATOR_P (olddecl))
	DECL_OVERLOADED_OPERATOR_CODE_RAW (newdecl)
	  = DECL_OVERLOADED_OPERATOR_CODE_RAW (olddecl);
      new_defines_function = DECL_INITIAL (newdecl) != NULL_TREE;

      /* Optionally warn about more than one declaration for the same
	 name, but don't warn about a function declaration followed by a
	 definition.  */
      if (warn_redundant_decls && ! DECL_ARTIFICIAL (olddecl)
	  && !(new_defines_function && DECL_INITIAL (olddecl) == NULL_TREE)
	  /* Don't warn about extern decl followed by definition.  */
	  && !(DECL_EXTERNAL (olddecl) && ! DECL_EXTERNAL (newdecl))
	  /* Don't warn if at least one is/was hidden.  */
	  && !(hiding || was_hidden)
	  /* Don't warn about declaration followed by specialization.  */
	  && (! DECL_TEMPLATE_SPECIALIZATION (newdecl)
	      || DECL_TEMPLATE_SPECIALIZATION (olddecl)))
	{
	  auto_diagnostic_group d;
	  if (warning_at (newdecl_loc,
			  OPT_Wredundant_decls,
			  "redundant redeclaration of %qD in same scope",
			  newdecl))
	    inform (olddecl_loc,
		    "previous declaration of %qD", olddecl);
	}

      /* [dcl.fct.def.delete] A deleted definition of a function shall be the
	 first declaration of the function or, for an explicit specialization
	 of a function template, the first declaration of that
	 specialization.  */
      if (!(DECL_TEMPLATE_INSTANTIATION (olddecl)
	    && DECL_TEMPLATE_SPECIALIZATION (newdecl)))
	{
	  if (DECL_DELETED_FN (newdecl))
	    {
	      auto_diagnostic_group d;
	      if (pedwarn (newdecl_loc, 0, "deleted definition of %qD "
			   "is not first declaration", newdecl))
		inform (olddecl_loc,
			"previous declaration of %qD", olddecl);
	    }
	  DECL_DELETED_FN (newdecl) |= DECL_DELETED_FN (olddecl);
	}
    }

  /* Deal with C++: must preserve virtual function table size.  */
  if (TREE_CODE (olddecl) == TYPE_DECL)
    {
      tree newtype = TREE_TYPE (newdecl);
      tree oldtype = TREE_TYPE (olddecl);

      if (newtype != error_mark_node && oldtype != error_mark_node
	  && TYPE_LANG_SPECIFIC (newtype) && TYPE_LANG_SPECIFIC (oldtype))
	CLASSTYPE_FRIEND_CLASSES (newtype)
	  = CLASSTYPE_FRIEND_CLASSES (oldtype);

      DECL_ORIGINAL_TYPE (newdecl) = DECL_ORIGINAL_TYPE (olddecl);
    }

  /* Copy all the DECL_... slots specified in the new decl except for
     any that we copy here from the old type.  */
  if (merge_attr)
    DECL_ATTRIBUTES (newdecl)
      = (*targetm.merge_decl_attributes) (olddecl, newdecl);
  else
    DECL_ATTRIBUTES (olddecl) = DECL_ATTRIBUTES (newdecl);

  if (TREE_CODE (newdecl) == TEMPLATE_DECL)
    {
      tree old_result = DECL_TEMPLATE_RESULT (olddecl);
      tree new_result = DECL_TEMPLATE_RESULT (newdecl);
      TREE_TYPE (olddecl) = TREE_TYPE (old_result);

      /* The new decl should not already have gathered any
	 specializations.  */
      gcc_assert (!DECL_TEMPLATE_SPECIALIZATIONS (newdecl));

      DECL_ATTRIBUTES (old_result)
	= (*targetm.merge_decl_attributes) (old_result, new_result);

      if (DECL_FUNCTION_TEMPLATE_P (newdecl))
	{
	  if (DECL_SOURCE_LOCATION (newdecl)
	      != DECL_SOURCE_LOCATION (olddecl))
	    {
	      /* Per C++11 8.3.6/4, default arguments cannot be added in
		 later declarations of a function template.  */
	      check_redeclaration_no_default_args (newdecl);
	      /* C++17 11.3.6/4: "If a friend declaration specifies a default
		 argument expression, that declaration... shall be the only
		 declaration of the function or function template in the
		 translation unit."  */
	      check_no_redeclaration_friend_default_args
		(old_result, new_result);

	      tree new_parms = DECL_INNERMOST_TEMPLATE_PARMS (newdecl);
	      tree old_parms = DECL_INNERMOST_TEMPLATE_PARMS (olddecl);
	      merge_default_template_args (new_parms, old_parms,
					   /*class_p=*/false);
	    }
	  if (!DECL_UNIQUE_FRIEND_P (new_result))
	    DECL_UNIQUE_FRIEND_P (old_result) = false;

	  check_default_args (newdecl);

	  if (GNU_INLINE_P (old_result) != GNU_INLINE_P (new_result)
	      && DECL_INITIAL (new_result))
	    {
	      if (DECL_INITIAL (old_result))
		DECL_UNINLINABLE (old_result) = 1;
	      else
		DECL_UNINLINABLE (old_result) = DECL_UNINLINABLE (new_result);
	      DECL_EXTERNAL (old_result) = DECL_EXTERNAL (new_result);
	      DECL_NOT_REALLY_EXTERN (old_result)
		= DECL_NOT_REALLY_EXTERN (new_result);
	      DECL_INTERFACE_KNOWN (old_result)
		= DECL_INTERFACE_KNOWN (new_result);
	      DECL_DECLARED_INLINE_P (old_result)
		= DECL_DECLARED_INLINE_P (new_result);
	      DECL_DISREGARD_INLINE_LIMITS (old_result)
	        |= DECL_DISREGARD_INLINE_LIMITS (new_result);

	    }
	  else
	    {
	      DECL_DECLARED_INLINE_P (old_result)
		|= DECL_DECLARED_INLINE_P (new_result);
	      DECL_DISREGARD_INLINE_LIMITS (old_result)
	        |= DECL_DISREGARD_INLINE_LIMITS (new_result);
	      check_redeclaration_exception_specification (newdecl, olddecl);

	      merge_attribute_bits (new_result, old_result);
	    }
	}

      /* If the new declaration is a definition, update the file and
	 line information on the declaration, and also make
	 the old declaration the same definition.  */
      if (DECL_INITIAL (new_result) != NULL_TREE)
	{
	  DECL_SOURCE_LOCATION (olddecl)
	    = DECL_SOURCE_LOCATION (old_result)
	    = DECL_SOURCE_LOCATION (newdecl);
	  DECL_INITIAL (old_result) = DECL_INITIAL (new_result);
	  if (DECL_FUNCTION_TEMPLATE_P (newdecl))
	    {
	      tree parm;
	      DECL_ARGUMENTS (old_result)
		= DECL_ARGUMENTS (new_result);
	      for (parm = DECL_ARGUMENTS (old_result); parm;
		   parm = DECL_CHAIN (parm))
		DECL_CONTEXT (parm) = old_result;

	      if (tree fc = DECL_FRIEND_CONTEXT (new_result))
		SET_DECL_FRIEND_CONTEXT (old_result, fc);
	    }
	}

      return olddecl;
    }

  if (types_match)
    {
      if (TREE_CODE (newdecl) == FUNCTION_DECL)
	check_redeclaration_exception_specification (newdecl, olddecl);

      /* Automatically handles default parameters.  */
      tree oldtype = TREE_TYPE (olddecl);
      tree newtype;

      /* For typedefs use the old type, as the new type's DECL_NAME points
	 at newdecl, which will be ggc_freed.  */
      if (TREE_CODE (newdecl) == TYPE_DECL)
	{
	  /* But NEWTYPE might have an attribute, honor that.  */
	  tree tem = TREE_TYPE (newdecl);
	  newtype = oldtype;

	  if (TYPE_USER_ALIGN (tem))
	    {
	      if (TYPE_ALIGN (tem) > TYPE_ALIGN (newtype))
		SET_TYPE_ALIGN (newtype, TYPE_ALIGN (tem));
	      TYPE_USER_ALIGN (newtype) = true;
	    }

	  /* And remove the new type from the variants list.  */
	  if (TYPE_NAME (TREE_TYPE (newdecl)) == newdecl)
	    {
	      tree remove = TREE_TYPE (newdecl);
	      if (TYPE_MAIN_VARIANT (remove) == remove)
		{
		  gcc_assert (TYPE_NEXT_VARIANT (remove) == NULL_TREE);
		  /* If remove is the main variant, no need to remove that
		     from the list.  One of the DECL_ORIGINAL_TYPE
		     variants, e.g. created for aligned attribute, might still
		     refer to the newdecl TYPE_DECL though, so remove that one
		     in that case.  */
		  if (tree orig = DECL_ORIGINAL_TYPE (newdecl))
		    if (orig != remove)
		      for (tree t = TYPE_MAIN_VARIANT (orig); t;
			   t = TYPE_MAIN_VARIANT (t))
			if (TYPE_NAME (TYPE_NEXT_VARIANT (t)) == newdecl)
			  {
			    TYPE_NEXT_VARIANT (t)
			      = TYPE_NEXT_VARIANT (TYPE_NEXT_VARIANT (t));
			    break;
			  }
		}	    
	      else
		for (tree t = TYPE_MAIN_VARIANT (remove); ;
		     t = TYPE_NEXT_VARIANT (t))
		  if (TYPE_NEXT_VARIANT (t) == remove)
		    {
		      TYPE_NEXT_VARIANT (t) = TYPE_NEXT_VARIANT (remove);
		      break;
		    }
	    }
	}
      else if (merge_attr)
	newtype = merge_types (TREE_TYPE (newdecl), TREE_TYPE (olddecl));
      else
	newtype = TREE_TYPE (newdecl);

      if (VAR_P (newdecl))
	{
	  DECL_THIS_EXTERN (newdecl) |= DECL_THIS_EXTERN (olddecl);
	  /* For already initialized vars, TREE_READONLY could have been
	     cleared in cp_finish_decl, because the var needs runtime
	     initialization or destruction.  Make sure not to set
	     TREE_READONLY on it again.  */
	  if (DECL_INITIALIZED_P (olddecl)
	      && !DECL_EXTERNAL (olddecl)
	      && !TREE_READONLY (olddecl))
	    TREE_READONLY (newdecl) = 0;
	  DECL_INITIALIZED_P (newdecl) |= DECL_INITIALIZED_P (olddecl);
	  DECL_NONTRIVIALLY_INITIALIZED_P (newdecl)
	    |= DECL_NONTRIVIALLY_INITIALIZED_P (olddecl);
	  if (DECL_DEPENDENT_INIT_P (olddecl))
	    SET_DECL_DEPENDENT_INIT_P (newdecl, true);
	  DECL_INITIALIZED_BY_CONSTANT_EXPRESSION_P (newdecl)
	    |= DECL_INITIALIZED_BY_CONSTANT_EXPRESSION_P (olddecl);
	  DECL_DECLARED_CONSTEXPR_P (newdecl)
	    |= DECL_DECLARED_CONSTEXPR_P (olddecl);
	  DECL_DECLARED_CONSTINIT_P (newdecl)
	    |= DECL_DECLARED_CONSTINIT_P (olddecl);

	  /* Merge the threadprivate attribute from OLDDECL into NEWDECL.  */
	  if (DECL_LANG_SPECIFIC (olddecl)
	      && CP_DECL_THREADPRIVATE_P (olddecl))
	    {
	      /* Allocate a LANG_SPECIFIC structure for NEWDECL, if needed.  */
	      retrofit_lang_decl (newdecl);
	      CP_DECL_THREADPRIVATE_P (newdecl) = 1;
	    }
	}

      /* An explicit specialization of a function template or of a member
	 function of a class template can be declared transaction_safe
	 independently of whether the corresponding template entity is declared
	 transaction_safe. */
      if (flag_tm && TREE_CODE (newdecl) == FUNCTION_DECL
	  && DECL_TEMPLATE_INSTANTIATION (olddecl)
	  && DECL_TEMPLATE_SPECIALIZATION (newdecl)
	  && tx_safe_fn_type_p (newtype)
	  && !tx_safe_fn_type_p (TREE_TYPE (newdecl)))
	newtype = tx_unsafe_fn_variant (newtype);

      TREE_TYPE (newdecl) = TREE_TYPE (olddecl) = newtype;

      if (TREE_CODE (newdecl) == FUNCTION_DECL)
	check_default_args (newdecl);

      /* Lay the type out, unless already done.  */
      if (! same_type_p (newtype, oldtype)
	  && TREE_TYPE (newdecl) != error_mark_node
	  && !(processing_template_decl && uses_template_parms (newdecl)))
	layout_type (TREE_TYPE (newdecl));

      if ((VAR_P (newdecl)
	   || TREE_CODE (newdecl) == PARM_DECL
	   || TREE_CODE (newdecl) == RESULT_DECL
	   || TREE_CODE (newdecl) == FIELD_DECL
	   || TREE_CODE (newdecl) == TYPE_DECL)
	  && !(processing_template_decl && uses_template_parms (newdecl)))
	layout_decl (newdecl, 0);

      /* Merge deprecatedness.  */
      if (TREE_DEPRECATED (newdecl))
	TREE_DEPRECATED (olddecl) = 1;

      /* Merge unavailability.  */
      if (TREE_UNAVAILABLE (newdecl))
	TREE_UNAVAILABLE (olddecl) = 1;

      /* Preserve function specific target and optimization options */
      if (TREE_CODE (newdecl) == FUNCTION_DECL)
	{
	  if (DECL_FUNCTION_SPECIFIC_TARGET (olddecl)
	      && !DECL_FUNCTION_SPECIFIC_TARGET (newdecl))
	    DECL_FUNCTION_SPECIFIC_TARGET (newdecl)
	      = DECL_FUNCTION_SPECIFIC_TARGET (olddecl);

	  if (DECL_FUNCTION_SPECIFIC_OPTIMIZATION (olddecl)
	      && !DECL_FUNCTION_SPECIFIC_OPTIMIZATION (newdecl))
	    DECL_FUNCTION_SPECIFIC_OPTIMIZATION (newdecl)
	      = DECL_FUNCTION_SPECIFIC_OPTIMIZATION (olddecl);

	  if (!DECL_UNIQUE_FRIEND_P (olddecl))
	    DECL_UNIQUE_FRIEND_P (newdecl) = false;
	}
      else
	{
	  /* Merge the const type qualifier.  */
	  if (TREE_READONLY (newdecl))
	    TREE_READONLY (olddecl) = 1;
	  /* Merge the volatile type qualifier.  */
	  if (TREE_THIS_VOLATILE (newdecl))
	    TREE_THIS_VOLATILE (olddecl) = 1;
	}

      /* Merge the initialization information.  */
      if (DECL_INITIAL (newdecl) == NULL_TREE
	  && DECL_INITIAL (olddecl) != NULL_TREE)
	{
	  DECL_INITIAL (newdecl) = DECL_INITIAL (olddecl);
	  DECL_SOURCE_LOCATION (newdecl) = DECL_SOURCE_LOCATION (olddecl);
	  if (TREE_CODE (newdecl) == FUNCTION_DECL)
	    {
	      DECL_SAVED_TREE (newdecl) = DECL_SAVED_TREE (olddecl);
	      DECL_STRUCT_FUNCTION (newdecl) = DECL_STRUCT_FUNCTION (olddecl);
	    }
	}

      if (TREE_CODE (newdecl) == FUNCTION_DECL)
	{
	  DECL_NO_INSTRUMENT_FUNCTION_ENTRY_EXIT (newdecl)
	    |= DECL_NO_INSTRUMENT_FUNCTION_ENTRY_EXIT (olddecl);
	  DECL_NO_LIMIT_STACK (newdecl) |= DECL_NO_LIMIT_STACK (olddecl);
	  if (DECL_IS_OPERATOR_NEW_P (olddecl))
	    DECL_SET_IS_OPERATOR_NEW (newdecl, true);
	  DECL_LOOPING_CONST_OR_PURE_P (newdecl)
	    |= DECL_LOOPING_CONST_OR_PURE_P (olddecl);
	  DECL_IS_REPLACEABLE_OPERATOR (newdecl)
	    |= DECL_IS_REPLACEABLE_OPERATOR (olddecl);

	  if (merge_attr)
	    merge_attribute_bits (newdecl, olddecl);
	  else
	    {
	      /* Merge the noreturn bit.  */
	      TREE_THIS_VOLATILE (olddecl) = TREE_THIS_VOLATILE (newdecl);
	      TREE_READONLY (olddecl) = TREE_READONLY (newdecl);
	      TREE_NOTHROW (olddecl) = TREE_NOTHROW (newdecl);
	      DECL_IS_MALLOC (olddecl) = DECL_IS_MALLOC (newdecl);
	      DECL_PURE_P (olddecl) = DECL_PURE_P (newdecl);
	    }
	  /* Keep the old RTL.  */
	  COPY_DECL_RTL (olddecl, newdecl);
	}
      else if (VAR_P (newdecl)
	       && (DECL_SIZE (olddecl) || !DECL_SIZE (newdecl)))
	{
	  /* Keep the old RTL.  We cannot keep the old RTL if the old
	     declaration was for an incomplete object and the new
	     declaration is not since many attributes of the RTL will
	     change.  */
	  COPY_DECL_RTL (olddecl, newdecl);
	}
    }
  /* If cannot merge, then use the new type and qualifiers,
     and don't preserve the old rtl.  */
  else
    {
      /* Clean out any memory we had of the old declaration.  */
      tree oldstatic = value_member (olddecl, static_aggregates);
      if (oldstatic)
	TREE_VALUE (oldstatic) = error_mark_node;

      TREE_TYPE (olddecl) = TREE_TYPE (newdecl);
      TREE_READONLY (olddecl) = TREE_READONLY (newdecl);
      TREE_THIS_VOLATILE (olddecl) = TREE_THIS_VOLATILE (newdecl);
      TREE_NOTHROW (olddecl) = TREE_NOTHROW (newdecl);
      TREE_SIDE_EFFECTS (olddecl) = TREE_SIDE_EFFECTS (newdecl);
    }

  /* Merge the storage class information.  */
  merge_weak (newdecl, olddecl);

  DECL_DEFER_OUTPUT (newdecl) |= DECL_DEFER_OUTPUT (olddecl);
  TREE_PUBLIC (newdecl) = TREE_PUBLIC (olddecl);
  TREE_STATIC (olddecl) = TREE_STATIC (newdecl) |= TREE_STATIC (olddecl);
  if (! DECL_EXTERNAL (olddecl))
    DECL_EXTERNAL (newdecl) = 0;
  if (! DECL_COMDAT (olddecl))
    DECL_COMDAT (newdecl) = 0;

  if (VAR_OR_FUNCTION_DECL_P (newdecl) && DECL_LOCAL_DECL_P (newdecl))
    {
      if (!DECL_LOCAL_DECL_P (olddecl))
	/* This can happen if olddecl was brought in from the
	   enclosing namespace via a using-decl.  The new decl is
	   then not a block-scope extern at all.  */
	DECL_LOCAL_DECL_P (newdecl) = false;
      else
	{
	  retrofit_lang_decl (newdecl);
	  tree alias = DECL_LOCAL_DECL_ALIAS (newdecl)
	    = DECL_LOCAL_DECL_ALIAS (olddecl);
	  DECL_ATTRIBUTES (alias)
	    = (*targetm.merge_decl_attributes) (alias, newdecl);
	  if (TREE_CODE (newdecl) == FUNCTION_DECL)
	    merge_attribute_bits (newdecl, alias);
	}
    }

  new_template_info = NULL_TREE;
  if (DECL_LANG_SPECIFIC (newdecl) && DECL_LANG_SPECIFIC (olddecl))
    {
      bool new_redefines_gnu_inline = false;

      if (new_defines_function
	  && ((DECL_INTERFACE_KNOWN (olddecl)
	       && TREE_CODE (olddecl) == FUNCTION_DECL)
	      || (TREE_CODE (olddecl) == TEMPLATE_DECL
		  && (TREE_CODE (DECL_TEMPLATE_RESULT (olddecl))
		      == FUNCTION_DECL))))
	new_redefines_gnu_inline = GNU_INLINE_P (STRIP_TEMPLATE (olddecl));

      if (!new_redefines_gnu_inline)
	{
	  DECL_INTERFACE_KNOWN (newdecl) |= DECL_INTERFACE_KNOWN (olddecl);
	  DECL_NOT_REALLY_EXTERN (newdecl) |= DECL_NOT_REALLY_EXTERN (olddecl);
	  DECL_COMDAT (newdecl) |= DECL_COMDAT (olddecl);
	}

      if (TREE_CODE (newdecl) != TYPE_DECL)
	{
	  DECL_TEMPLATE_INSTANTIATED (newdecl)
	    |= DECL_TEMPLATE_INSTANTIATED (olddecl);
	  DECL_ODR_USED (newdecl) |= DECL_ODR_USED (olddecl);

	  /* If the OLDDECL is an instantiation and/or specialization,
	     then the NEWDECL must be too.  But, it may not yet be marked
	     as such if the caller has created NEWDECL, but has not yet
	     figured out that it is a redeclaration.  */
	  if (!DECL_USE_TEMPLATE (newdecl))
	    DECL_USE_TEMPLATE (newdecl) = DECL_USE_TEMPLATE (olddecl);

	  if (!DECL_TEMPLATE_SPECIALIZATION (newdecl))
	    DECL_INITIALIZED_IN_CLASS_P (newdecl)
	      |= DECL_INITIALIZED_IN_CLASS_P (olddecl);
	}

      /* Don't really know how much of the language-specific
	 values we should copy from old to new.  */
      DECL_IN_AGGR_P (newdecl) = DECL_IN_AGGR_P (olddecl);

      if (LANG_DECL_HAS_MIN (newdecl))
	{
	  DECL_ACCESS (newdecl) = DECL_ACCESS (olddecl);
	  if (DECL_TEMPLATE_INFO (newdecl))
	    {
	      new_template_info = DECL_TEMPLATE_INFO (newdecl);
	      if (DECL_TEMPLATE_INSTANTIATION (olddecl)
		  && DECL_TEMPLATE_SPECIALIZATION (newdecl))
		/* Remember the presence of explicit specialization args.  */
		TINFO_USED_TEMPLATE_ID (DECL_TEMPLATE_INFO (olddecl))
		  = TINFO_USED_TEMPLATE_ID (new_template_info);
	    }

	  /* We don't want to copy template info from a non-templated friend
	     (PR105761), but these shouldn't have DECL_TEMPLATE_INFO now.  */
	  gcc_checking_assert (!DECL_TEMPLATE_INFO (olddecl)
			       || !non_templated_friend_p (olddecl));
	  DECL_TEMPLATE_INFO (newdecl) = DECL_TEMPLATE_INFO (olddecl);
	}

      if (DECL_DECLARES_FUNCTION_P (newdecl))
	{
	  /* Only functions have these fields.  */
	  DECL_NONCONVERTING_P (newdecl) = DECL_NONCONVERTING_P (olddecl);
	  DECL_BEFRIENDING_CLASSES (newdecl)
	    = chainon (DECL_BEFRIENDING_CLASSES (newdecl),
		       DECL_BEFRIENDING_CLASSES (olddecl));
	  /* DECL_THUNKS is only valid for virtual functions,
	     otherwise it is a DECL_FRIEND_CONTEXT.  */
	  if (DECL_VIRTUAL_P (newdecl))
	    SET_DECL_THUNKS (newdecl, DECL_THUNKS (olddecl));
	  else if (tree fc = DECL_FRIEND_CONTEXT (newdecl))
	    SET_DECL_FRIEND_CONTEXT (olddecl, fc);
	}
      else if (VAR_P (newdecl))
	{
	  /* Only variables have this field.  */
	  if (VAR_HAD_UNKNOWN_BOUND (olddecl))
	    SET_VAR_HAD_UNKNOWN_BOUND (newdecl);
	}
    }

  if (TREE_CODE (newdecl) == FUNCTION_DECL)
    {
      tree parm;

      /* Merge parameter attributes. */
      tree oldarg, newarg;
      for (oldarg = DECL_ARGUMENTS(olddecl), newarg = DECL_ARGUMENTS(newdecl);
           oldarg && newarg;
           oldarg = DECL_CHAIN(oldarg), newarg = DECL_CHAIN(newarg))
	{
          DECL_ATTRIBUTES (newarg)
	    = (*targetm.merge_decl_attributes) (oldarg, newarg);
          DECL_ATTRIBUTES (oldarg) = DECL_ATTRIBUTES (newarg);
	}

      if (DECL_TEMPLATE_INSTANTIATION (olddecl)
	  && !DECL_TEMPLATE_INSTANTIATION (newdecl))
	{
	  /* If newdecl is not a specialization, then it is not a
	     template-related function at all.  And that means that we
	     should have exited above, returning 0.  */
	  gcc_assert (DECL_TEMPLATE_SPECIALIZATION (newdecl));

	  if (DECL_ODR_USED (olddecl))
	    /* From [temp.expl.spec]:

	       If a template, a member template or the member of a class
	       template is explicitly specialized then that
	       specialization shall be declared before the first use of
	       that specialization that would cause an implicit
	       instantiation to take place, in every translation unit in
	       which such a use occurs.  */
	    error ("explicit specialization of %qD after first use",
		      olddecl);

	  SET_DECL_TEMPLATE_SPECIALIZATION (olddecl);
	  DECL_COMDAT (newdecl) = (TREE_PUBLIC (newdecl)
				   && DECL_DECLARED_INLINE_P (newdecl));

	  /* Don't propagate visibility from the template to the
	     specialization here.  We'll do that in determine_visibility if
	     appropriate.  */
	  DECL_VISIBILITY_SPECIFIED (olddecl) = 0;

	  /* [temp.expl.spec/14] We don't inline explicit specialization
	     just because the primary template says so.  */
	  gcc_assert (!merge_attr);

	  DECL_DECLARED_INLINE_P (olddecl)
	    = DECL_DECLARED_INLINE_P (newdecl);

	  DECL_DISREGARD_INLINE_LIMITS (olddecl)
	    = DECL_DISREGARD_INLINE_LIMITS (newdecl);

	  DECL_UNINLINABLE (olddecl) = DECL_UNINLINABLE (newdecl);
	}
      else if (new_defines_function && DECL_INITIAL (olddecl))
	{
	  /* Never inline re-defined extern inline functions.
	     FIXME: this could be better handled by keeping both
	     function as separate declarations.  */
	  DECL_UNINLINABLE (newdecl) = 1;
	}
      else
	{
	  if (DECL_PENDING_INLINE_P (olddecl))
	    {
	      DECL_PENDING_INLINE_P (newdecl) = 1;
	      DECL_PENDING_INLINE_INFO (newdecl)
		= DECL_PENDING_INLINE_INFO (olddecl);
	    }
	  else if (DECL_PENDING_INLINE_P (newdecl))
	    ;
	  else if (DECL_SAVED_AUTO_RETURN_TYPE (newdecl) == NULL)
	    DECL_SAVED_AUTO_RETURN_TYPE (newdecl)
	      = DECL_SAVED_AUTO_RETURN_TYPE (olddecl);

	  DECL_DECLARED_INLINE_P (newdecl) |= DECL_DECLARED_INLINE_P (olddecl);

	  DECL_UNINLINABLE (newdecl) = DECL_UNINLINABLE (olddecl)
	    = (DECL_UNINLINABLE (newdecl) || DECL_UNINLINABLE (olddecl));

	  DECL_DISREGARD_INLINE_LIMITS (newdecl)
	    = DECL_DISREGARD_INLINE_LIMITS (olddecl)
	    = (DECL_DISREGARD_INLINE_LIMITS (newdecl)
	       || DECL_DISREGARD_INLINE_LIMITS (olddecl));
	}

      /* Preserve abstractness on cloned [cd]tors.  */
      DECL_ABSTRACT_P (newdecl) = DECL_ABSTRACT_P (olddecl);

      /* Update newdecl's parms to point at olddecl.  */
      for (parm = DECL_ARGUMENTS (newdecl); parm;
	   parm = DECL_CHAIN (parm))
	DECL_CONTEXT (parm) = olddecl;

      if (! types_match)
	{
	  SET_DECL_LANGUAGE (olddecl, DECL_LANGUAGE (newdecl));
	  COPY_DECL_ASSEMBLER_NAME (newdecl, olddecl);
	  COPY_DECL_RTL (newdecl, olddecl);
	}
      if (! types_match || new_defines_function)
	{
	  /* These need to be copied so that the names are available.
	     Note that if the types do match, we'll preserve inline
	     info and other bits, but if not, we won't.  */
	  DECL_ARGUMENTS (olddecl) = DECL_ARGUMENTS (newdecl);
	  DECL_RESULT (olddecl) = DECL_RESULT (newdecl);
	}
      /* If redeclaring a builtin function, it stays built in
	 if newdecl is a gnu_inline definition, or if newdecl is just
	 a declaration.  */
      if (fndecl_built_in_p (olddecl)
	  && (new_defines_function ? GNU_INLINE_P (newdecl) : types_match))
	{
	  copy_decl_built_in_function (newdecl, olddecl);
	  /* If we're keeping the built-in definition, keep the rtl,
	     regardless of declaration matches.  */
	  COPY_DECL_RTL (olddecl, newdecl);
	  if (DECL_BUILT_IN_CLASS (newdecl) == BUILT_IN_NORMAL)
	    {
	      enum built_in_function fncode = DECL_FUNCTION_CODE (newdecl);
	      if (builtin_decl_explicit_p (fncode))
		{
		  /* A compatible prototype of these builtin functions
		     is seen, assume the runtime implements it with
		     the expected semantics.  */
		  switch (fncode)
		    {
		    case BUILT_IN_STPCPY:
		      set_builtin_decl_implicit_p (fncode, true);
		      break;
		    default:
		      set_builtin_decl_declared_p (fncode, true);
		      break;
		    }
		}

	      copy_attributes_to_builtin (newdecl);
	    }
	}
      if (new_defines_function)
	/* If defining a function declared with other language
	   linkage, use the previously declared language linkage.  */
	SET_DECL_LANGUAGE (newdecl, DECL_LANGUAGE (olddecl));
      else if (types_match)
	{
	  DECL_RESULT (newdecl) = DECL_RESULT (olddecl);
	  /* Don't clear out the arguments if we're just redeclaring a
	     function.  */
	  if (DECL_ARGUMENTS (olddecl))
	    DECL_ARGUMENTS (newdecl) = DECL_ARGUMENTS (olddecl);
	}
    }
  else if (TREE_CODE (newdecl) == NAMESPACE_DECL)
    NAMESPACE_LEVEL (newdecl) = NAMESPACE_LEVEL (olddecl);

  /* Now preserve various other info from the definition.  */
  TREE_ADDRESSABLE (newdecl) = TREE_ADDRESSABLE (olddecl);
  TREE_ASM_WRITTEN (newdecl) = TREE_ASM_WRITTEN (olddecl);
  DECL_COMMON (newdecl) = DECL_COMMON (olddecl);
  COPY_DECL_ASSEMBLER_NAME (olddecl, newdecl);

  /* Warn about conflicting visibility specifications.  */
  if (DECL_VISIBILITY_SPECIFIED (olddecl)
      && DECL_VISIBILITY_SPECIFIED (newdecl)
      && DECL_VISIBILITY (newdecl) != DECL_VISIBILITY (olddecl))
    {
      auto_diagnostic_group d;
      if (warning_at (newdecl_loc, OPT_Wattributes,
		      "%qD: visibility attribute ignored because it "
		      "conflicts with previous declaration", newdecl))
	inform (olddecl_loc,
		"previous declaration of %qD", olddecl);
    }
  /* Choose the declaration which specified visibility.  */
  if (DECL_VISIBILITY_SPECIFIED (olddecl))
    {
      DECL_VISIBILITY (newdecl) = DECL_VISIBILITY (olddecl);
      DECL_VISIBILITY_SPECIFIED (newdecl) = 1;
    }
  /* Init priority used to be merged from newdecl to olddecl by the memcpy,
     so keep this behavior.  */
  if (VAR_P (newdecl) && DECL_HAS_INIT_PRIORITY_P (newdecl))
    {
      SET_DECL_INIT_PRIORITY (olddecl, DECL_INIT_PRIORITY (newdecl));
      DECL_HAS_INIT_PRIORITY_P (olddecl) = 1;
    }
  /* Likewise for DECL_ALIGN, DECL_USER_ALIGN and DECL_PACKED.  */
  if (DECL_ALIGN (olddecl) > DECL_ALIGN (newdecl))
    {
      SET_DECL_ALIGN (newdecl, DECL_ALIGN (olddecl));
      DECL_USER_ALIGN (newdecl) |= DECL_USER_ALIGN (olddecl);
    }
  else if (DECL_ALIGN (olddecl) == DECL_ALIGN (newdecl)
      && DECL_USER_ALIGN (olddecl) != DECL_USER_ALIGN (newdecl))
    DECL_USER_ALIGN (newdecl) = 1;

  DECL_USER_ALIGN (olddecl) = DECL_USER_ALIGN (newdecl);
  if (DECL_WARN_IF_NOT_ALIGN (olddecl)
      > DECL_WARN_IF_NOT_ALIGN (newdecl))
    SET_DECL_WARN_IF_NOT_ALIGN (newdecl,
				DECL_WARN_IF_NOT_ALIGN (olddecl));
  if (TREE_CODE (newdecl) == FIELD_DECL)
    DECL_PACKED (olddecl) = DECL_PACKED (newdecl);

  /* The DECL_LANG_SPECIFIC information in OLDDECL will be replaced
     with that from NEWDECL below.  */
  if (DECL_LANG_SPECIFIC (olddecl))
    {
      gcc_checking_assert (DECL_LANG_SPECIFIC (olddecl)
			   != DECL_LANG_SPECIFIC (newdecl));
      ggc_free (DECL_LANG_SPECIFIC (olddecl));
    }

  /* Merge the USED information.  */
  if (TREE_USED (olddecl))
    TREE_USED (newdecl) = 1;
  else if (TREE_USED (newdecl))
    TREE_USED (olddecl) = 1;

  if (VAR_P (newdecl))
    {
      if (DECL_READ_P (olddecl))
	DECL_READ_P (newdecl) = 1;
      else if (DECL_READ_P (newdecl))
	DECL_READ_P (olddecl) = 1;
    }

  if (DECL_PRESERVE_P (olddecl))
    DECL_PRESERVE_P (newdecl) = 1;
  else if (DECL_PRESERVE_P (newdecl))
    DECL_PRESERVE_P (olddecl) = 1;

  /* Merge the DECL_FUNCTION_VERSIONED information.  newdecl will be copied
     to olddecl and deleted.  */
  if (TREE_CODE (newdecl) == FUNCTION_DECL
      && DECL_FUNCTION_VERSIONED (olddecl))
    {
      /* Set the flag for newdecl so that it gets copied to olddecl.  */
      DECL_FUNCTION_VERSIONED (newdecl) = 1;
      /* newdecl will be purged after copying to olddecl and is no longer
         a version.  */
      cgraph_node::delete_function_version_by_decl (newdecl);
    }

  if (TREE_CODE (newdecl) == FUNCTION_DECL)
    {
      int function_size;
      struct symtab_node *snode = symtab_node::get (olddecl);

      function_size = sizeof (struct tree_decl_common);

      memcpy ((char *) olddecl + sizeof (struct tree_common),
	      (char *) newdecl + sizeof (struct tree_common),
	      function_size - sizeof (struct tree_common));

      memcpy ((char *) olddecl + sizeof (struct tree_decl_common),
	      (char *) newdecl + sizeof (struct tree_decl_common),
	      sizeof (struct tree_function_decl) - sizeof (struct tree_decl_common));

      /* Preserve symtab node mapping.  */
      olddecl->decl_with_vis.symtab_node = snode;

      if (new_template_info)
	/* If newdecl is a template instantiation, it is possible that
	   the following sequence of events has occurred:

	   o A friend function was declared in a class template.  The
	   class template was instantiated.

	   o The instantiation of the friend declaration was
	   recorded on the instantiation list, and is newdecl.

	   o Later, however, instantiate_class_template called pushdecl
	   on the newdecl to perform name injection.  But, pushdecl in
	   turn called duplicate_decls when it discovered that another
	   declaration of a global function with the same name already
	   existed.

	   o Here, in duplicate_decls, we decided to clobber newdecl.

	   If we're going to do that, we'd better make sure that
	   olddecl, and not newdecl, is on the list of
	   instantiations so that if we try to do the instantiation
	   again we won't get the clobbered declaration.  */
	reregister_specialization (newdecl,
				   new_template_info,
				   olddecl);
    }
  else
    {
      size_t size = tree_code_size (TREE_CODE (newdecl));

      memcpy ((char *) olddecl + sizeof (struct tree_common),
	      (char *) newdecl + sizeof (struct tree_common),
	      sizeof (struct tree_decl_common) - sizeof (struct tree_common));

      switch (TREE_CODE (newdecl))
	{
	case LABEL_DECL:
	case VAR_DECL:
	case RESULT_DECL:
	case PARM_DECL:
	case FIELD_DECL:
	case TYPE_DECL:
	case CONST_DECL:
	  {
            struct symtab_node *snode = NULL;

	    if (VAR_P (newdecl)
		&& (TREE_STATIC (olddecl) || TREE_PUBLIC (olddecl)
		    || DECL_EXTERNAL (olddecl)))
	      snode = symtab_node::get (olddecl);
	    memcpy ((char *) olddecl + sizeof (struct tree_decl_common),
		    (char *) newdecl + sizeof (struct tree_decl_common),
		    size - sizeof (struct tree_decl_common)
		    + TREE_CODE_LENGTH (TREE_CODE (newdecl)) * sizeof (char *));
	    if (VAR_P (newdecl))
	      olddecl->decl_with_vis.symtab_node = snode;
	  }
	  break;
	default:
	  memcpy ((char *) olddecl + sizeof (struct tree_decl_common),
		  (char *) newdecl + sizeof (struct tree_decl_common),
		  sizeof (struct tree_decl_non_common) - sizeof (struct tree_decl_common)
		  + TREE_CODE_LENGTH (TREE_CODE (newdecl)) * sizeof (char *));
	  break;
	}
    }

  if (VAR_OR_FUNCTION_DECL_P (newdecl))
    {
      if (DECL_EXTERNAL (olddecl)
	  || TREE_PUBLIC (olddecl)
	  || TREE_STATIC (olddecl))
	{
	  /* Merge the section attribute.
	     We want to issue an error if the sections conflict but that must be
	     done later in decl_attributes since we are called before attributes
	     are assigned.  */
	  if (DECL_SECTION_NAME (newdecl) != NULL)
	    set_decl_section_name (olddecl, newdecl);

	  if (DECL_ONE_ONLY (newdecl))
	    {
	      struct symtab_node *oldsym, *newsym;
	      if (TREE_CODE (olddecl) == FUNCTION_DECL)
		oldsym = cgraph_node::get_create (olddecl);
	      else
		oldsym = varpool_node::get_create (olddecl);
	      newsym = symtab_node::get (newdecl);
	      oldsym->set_comdat_group (newsym->get_comdat_group ());
	    }
	}

      if (VAR_P (newdecl)
	  && CP_DECL_THREAD_LOCAL_P (newdecl))
	{
	  CP_DECL_THREAD_LOCAL_P (olddecl) = true;
	  if (!processing_template_decl)
	    set_decl_tls_model (olddecl, DECL_TLS_MODEL (newdecl));
	}
    }

  DECL_UID (olddecl) = olddecl_uid;

  /* NEWDECL contains the merged attribute lists.
     Update OLDDECL to be the same.  */
  DECL_ATTRIBUTES (olddecl) = DECL_ATTRIBUTES (newdecl);

  /* If OLDDECL had its DECL_RTL instantiated, re-invoke make_decl_rtl
    so that encode_section_info has a chance to look at the new decl
    flags and attributes.  */
  if (DECL_RTL_SET_P (olddecl)
      && (TREE_CODE (olddecl) == FUNCTION_DECL
	  || (VAR_P (olddecl)
	      && TREE_STATIC (olddecl))))
    make_decl_rtl (olddecl);

  /* The NEWDECL will no longer be needed.  Because every out-of-class
     declaration of a member results in a call to duplicate_decls,
     freeing these nodes represents in a significant savings.

     Before releasing the node, be sore to remove function from symbol
     table that might have been inserted there to record comdat group.
     Be sure to however do not free DECL_STRUCT_FUNCTION because this
     structure is shared in between newdecl and oldecl.  */
  if (TREE_CODE (newdecl) == FUNCTION_DECL)
    DECL_STRUCT_FUNCTION (newdecl) = NULL;
  if (VAR_OR_FUNCTION_DECL_P (newdecl))
    {
      struct symtab_node *snode = symtab_node::get (newdecl);
      if (snode)
	snode->remove ();
    }

  if (TREE_CODE (olddecl) == FUNCTION_DECL)
    {
      tree clone;
      FOR_EACH_CLONE (clone, olddecl)
	{
	  DECL_ATTRIBUTES (clone) = DECL_ATTRIBUTES (olddecl);
	  DECL_PRESERVE_P (clone) |= DECL_PRESERVE_P (olddecl);
	}
    }

  /* Remove the associated constraints for newdecl, if any, before
     reclaiming memory. */
  if (flag_concepts)
    remove_constraints (newdecl);

  ggc_free (newdecl);

  return olddecl;
}

/* Return zero if the declaration NEWDECL is valid
   when the declaration OLDDECL (assumed to be for the same name)
   has already been seen.
   Otherwise return an error message format string with a %s
   where the identifier should go.  */

static const char *
redeclaration_error_message (tree newdecl, tree olddecl)
{
  if (TREE_CODE (newdecl) == TYPE_DECL)
    {
      /* Because C++ can put things into name space for free,
	 constructs like "typedef struct foo { ... } foo"
	 would look like an erroneous redeclaration.  */
      if (same_type_p (TREE_TYPE (newdecl), TREE_TYPE (olddecl)))
	return NULL;
      else
	return G_("redefinition of %q#D");
    }
  else if (TREE_CODE (newdecl) == FUNCTION_DECL)
    {
      /* If this is a pure function, its olddecl will actually be
	 the original initialization to `0' (which we force to call
	 abort()).  Don't complain about redefinition in this case.  */
      if (DECL_LANG_SPECIFIC (olddecl) && DECL_PURE_VIRTUAL_P (olddecl)
	  && DECL_INITIAL (olddecl) == NULL_TREE)
	return NULL;

      /* If both functions come from different namespaces, this is not
	 a redeclaration - this is a conflict with a used function.  */
      if (DECL_NAMESPACE_SCOPE_P (olddecl)
	  && DECL_CONTEXT (olddecl) != DECL_CONTEXT (newdecl)
	  && ! decls_match (olddecl, newdecl))
	return G_("%qD conflicts with used function");

      /* We'll complain about linkage mismatches in
	 warn_extern_redeclared_static.  */

      /* Defining the same name twice is no good.  */
      if (decl_defined_p (olddecl)
	  && decl_defined_p (newdecl))
	{
	  if (DECL_NAME (olddecl) == NULL_TREE)
	    return G_("%q#D not declared in class");
	  else if (!GNU_INLINE_P (olddecl)
		   || GNU_INLINE_P (newdecl))
	    return G_("redefinition of %q#D");
	}

      if (DECL_DECLARED_INLINE_P (olddecl) && DECL_DECLARED_INLINE_P (newdecl))
	{
	  bool olda = GNU_INLINE_P (olddecl);
	  bool newa = GNU_INLINE_P (newdecl);

	  if (olda != newa)
	    {
	      if (newa)
		return G_("%q+D redeclared inline with "
			  "%<gnu_inline%> attribute");
	      else
		return G_("%q+D redeclared inline without "
			  "%<gnu_inline%> attribute");
	    }
	}

      if (deduction_guide_p (olddecl)
	  && deduction_guide_p (newdecl))
	return G_("deduction guide %q+D redeclared");

      /* [class.compare.default]: A definition of a comparison operator as
	 defaulted that appears in a class shall be the first declaration of
	 that function.  */
      special_function_kind sfk = special_function_p (olddecl);
      if (sfk == sfk_comparison && DECL_DEFAULTED_FN (newdecl))
	return G_("comparison operator %q+D defaulted after "
		  "its first declaration");

      check_abi_tag_redeclaration
	(olddecl, lookup_attribute ("abi_tag", DECL_ATTRIBUTES (olddecl)),
	 lookup_attribute ("abi_tag", DECL_ATTRIBUTES (newdecl)));

      return NULL;
    }
  else if (TREE_CODE (newdecl) == TEMPLATE_DECL)
    {
      tree nt, ot;

      if (TREE_CODE (DECL_TEMPLATE_RESULT (newdecl)) == CONCEPT_DECL)
        return G_("redefinition of %q#D");

      if (TREE_CODE (DECL_TEMPLATE_RESULT (newdecl)) != FUNCTION_DECL)
	return redeclaration_error_message (DECL_TEMPLATE_RESULT (newdecl),
					    DECL_TEMPLATE_RESULT (olddecl));

      if (DECL_TEMPLATE_RESULT (newdecl) == DECL_TEMPLATE_RESULT (olddecl))
	return NULL;

      nt = DECL_TEMPLATE_RESULT (newdecl);
      if (DECL_TEMPLATE_INFO (nt))
	nt = DECL_TEMPLATE_RESULT (template_for_substitution (nt));
      ot = DECL_TEMPLATE_RESULT (olddecl);
      if (DECL_TEMPLATE_INFO (ot))
	ot = DECL_TEMPLATE_RESULT (template_for_substitution (ot));
      if (DECL_INITIAL (nt) && DECL_INITIAL (ot)
	  && (!GNU_INLINE_P (ot) || GNU_INLINE_P (nt)))
	return G_("redefinition of %q#D");

      if (DECL_DECLARED_INLINE_P (ot) && DECL_DECLARED_INLINE_P (nt))
	{
	  bool olda = GNU_INLINE_P (ot);
	  bool newa = GNU_INLINE_P (nt);

	  if (olda != newa)
	    {
	      if (newa)
		return G_("%q+D redeclared inline with "
			  "%<gnu_inline%> attribute");
	      else
		return G_("%q+D redeclared inline without "
			  "%<gnu_inline%> attribute");
	    }
	}

      if (deduction_guide_p (olddecl)
	  && deduction_guide_p (newdecl))
	return G_("deduction guide %q+D redeclared");

      /* Core issue #226 (C++11):

           If a friend function template declaration specifies a
           default template-argument, that declaration shall be a
           definition and shall be the only declaration of the
           function template in the translation unit.  */
      if ((cxx_dialect != cxx98)
          && TREE_CODE (ot) == FUNCTION_DECL && DECL_UNIQUE_FRIEND_P (ot)
	  && !check_default_tmpl_args (nt, DECL_TEMPLATE_PARMS (newdecl),
                                       /*is_primary=*/true,
				       /*is_partial=*/false,
                                       /*is_friend_decl=*/2))
        return G_("redeclaration of friend %q#D "
		  "may not have default template arguments");

      return NULL;
    }
  else if (VAR_P (newdecl)
	   && (CP_DECL_THREAD_LOCAL_P (newdecl)
	       != CP_DECL_THREAD_LOCAL_P (olddecl))
	   && (! DECL_LANG_SPECIFIC (olddecl)
	       || ! CP_DECL_THREADPRIVATE_P (olddecl)
	       || CP_DECL_THREAD_LOCAL_P (newdecl)))
    {
      /* Only variables can be thread-local, and all declarations must
	 agree on this property.  */
      if (CP_DECL_THREAD_LOCAL_P (newdecl))
	return G_("thread-local declaration of %q#D follows "
	          "non-thread-local declaration");
      else
	return G_("non-thread-local declaration of %q#D follows "
	          "thread-local declaration");
    }
  else if (toplevel_bindings_p () || DECL_NAMESPACE_SCOPE_P (newdecl))
    {
      /* The objects have been declared at namespace scope.  If either
	 is a member of an anonymous union, then this is an invalid
	 redeclaration.  For example:

	   int i;
	   union { int i; };

	   is invalid.  */
      if ((VAR_P (newdecl) && DECL_ANON_UNION_VAR_P (newdecl))
	  || (VAR_P (olddecl) && DECL_ANON_UNION_VAR_P (olddecl)))
	return G_("redeclaration of %q#D");
      /* If at least one declaration is a reference, there is no
	 conflict.  For example:

	   int i = 3;
	   extern int i;

	 is valid.  */
      if (DECL_EXTERNAL (newdecl) || DECL_EXTERNAL (olddecl))
	return NULL;

      /* Static data member declared outside a class definition
	 if the variable is defined within the class with constexpr
	 specifier is declaration rather than definition (and
	 deprecated).  */
      if (cxx_dialect >= cxx17
	  && VAR_P (olddecl)
	  && DECL_CLASS_SCOPE_P (olddecl)
	  && DECL_DECLARED_CONSTEXPR_P (olddecl)
	  && !DECL_INITIAL (newdecl))
	{
	  DECL_EXTERNAL (newdecl) = 1;
	  /* For now, only warn with explicit -Wdeprecated.  */
	  if (OPTION_SET_P (warn_deprecated))
	    {
	      auto_diagnostic_group d;
	      if (warning_at (DECL_SOURCE_LOCATION (newdecl), OPT_Wdeprecated,
				"redundant redeclaration of %<constexpr%> "
				"static data member %qD", newdecl))
		inform (DECL_SOURCE_LOCATION (olddecl),
			  "previous declaration of %qD", olddecl);
	    }
	  return NULL;
	}

      /* Reject two definitions.  */
      return G_("redefinition of %q#D");
    }
  else
    {
      /* Objects declared with block scope:  */
      /* Reject two definitions, and reject a definition
	 together with an external reference.  */
      if (!(DECL_EXTERNAL (newdecl) && DECL_EXTERNAL (olddecl)))
	return G_("redeclaration of %q#D");
      return NULL;
    }
}


/* Hash and equality functions for the named_label table.  */

hashval_t
named_label_hash::hash (const value_type entry)
{
  return IDENTIFIER_HASH_VALUE (entry->name);
}

bool
named_label_hash::equal (const value_type entry, compare_type name)
{
  return name == entry->name;
}

/* Look for a label named ID in the current function.  If one cannot
   be found, create one.  Return the named_label_entry, or NULL on
   failure.  */

static named_label_entry *
lookup_label_1 (tree id, bool making_local_p)
{
  auto_cond_timevar tv (TV_NAME_LOOKUP);

  /* You can't use labels at global scope.  */
  if (current_function_decl == NULL_TREE)
    {
      error ("label %qE referenced outside of any function", id);
      return NULL;
    }

  if (!named_labels)
    named_labels = hash_table<named_label_hash>::create_ggc (13);

  hashval_t hash = IDENTIFIER_HASH_VALUE (id);
  named_label_entry **slot
    = named_labels->find_slot_with_hash (id, hash, INSERT);
  named_label_entry *old = *slot;
  
  if (old && old->label_decl)
    {
      if (!making_local_p)
	return old;

      if (old->binding_level == current_binding_level)
	{
	  error ("local label %qE conflicts with existing label", id);
	  inform (DECL_SOURCE_LOCATION (old->label_decl), "previous label");
	  return NULL;
	}
    }

  /* We are making a new decl, create or reuse the named_label_entry  */
  named_label_entry *ent = NULL;
  if (old && !old->label_decl)
    ent = old;
  else
    {
      ent = ggc_cleared_alloc<named_label_entry> ();
      ent->name = id;
      ent->outer = old;
      *slot = ent;
    }

  /* Now create the LABEL_DECL.  */
  tree decl = build_decl (input_location, LABEL_DECL, id, void_type_node);

  DECL_CONTEXT (decl) = current_function_decl;
  SET_DECL_MODE (decl, VOIDmode);
  if (making_local_p)
    {
      C_DECLARED_LABEL_FLAG (decl) = true;
      DECL_CHAIN (decl) = current_binding_level->names;
      current_binding_level->names = decl;
    }

  ent->label_decl = decl;

  return ent;
}

/* Wrapper for lookup_label_1.  */

tree
lookup_label (tree id)
{
  named_label_entry *ent = lookup_label_1 (id, false);
  return ent ? ent->label_decl : NULL_TREE;
}

tree
declare_local_label (tree id)
{
  named_label_entry *ent = lookup_label_1 (id, true);
  return ent ? ent->label_decl : NULL_TREE;
}

/* Returns nonzero if it is ill-formed to jump past the declaration of
   DECL.  Returns 2 if it's also a real problem.  */

static int
decl_jump_unsafe (tree decl)
{
  /* [stmt.dcl]/3: A program that jumps from a point where a local variable
     with automatic storage duration is not in scope to a point where it is
     in scope is ill-formed unless the variable has scalar type, class type
     with a trivial default constructor and a trivial destructor, a
     cv-qualified version of one of these types, or an array of one of the
     preceding types and is declared without an initializer (8.5).  */
  tree type = TREE_TYPE (decl);

  if (!VAR_P (decl) || TREE_STATIC (decl)
      || type == error_mark_node)
    return 0;

  if (DECL_NONTRIVIALLY_INITIALIZED_P (decl)
      || variably_modified_type_p (type, NULL_TREE))
    return 2;

  if (TYPE_HAS_NONTRIVIAL_DESTRUCTOR (type))
    return 1;

  return 0;
}

/* A subroutine of check_previous_goto_1 and check_goto to identify a branch
   to the user.  */

static bool
identify_goto (tree decl, location_t loc, const location_t *locus,
	       diagnostic_t diag_kind)
{
  bool complained
    = emit_diagnostic (diag_kind, loc, 0,
		       decl ? N_("jump to label %qD")
		       : N_("jump to case label"), decl);
  if (complained && locus)
    inform (*locus, "  from here");
  return complained;
}

/* Check that a single previously seen jump to a newly defined label
   is OK.  DECL is the LABEL_DECL or 0; LEVEL is the binding_level for
   the jump context; NAMES are the names in scope in LEVEL at the jump
   context; LOCUS is the source position of the jump or 0.  Returns
   true if all is well.  */

static bool
check_previous_goto_1 (tree decl, cp_binding_level* level, tree names,
		       bool exited_omp, const location_t *locus)
{
  cp_binding_level *b;
  bool complained = false;
  int identified = 0;
  bool saw_eh = false, saw_omp = false, saw_tm = false, saw_cxif = false;
  bool saw_ceif = false;

  if (exited_omp)
    {
      complained = identify_goto (decl, input_location, locus, DK_ERROR);
      if (complained)
	inform (input_location, "  exits OpenMP structured block");
      saw_omp = true;
      identified = 2;
    }

  for (b = current_binding_level; b ; b = b->level_chain)
    {
      tree new_decls, old_decls = (b == level ? names : NULL_TREE);

      for (new_decls = b->names; new_decls != old_decls;
	   new_decls = (DECL_P (new_decls) ? DECL_CHAIN (new_decls)
			: TREE_CHAIN (new_decls)))
	{
	  int problem = decl_jump_unsafe (new_decls);
	  if (! problem)
	    continue;

	  if (!identified)
	    {
	      complained = identify_goto (decl, input_location, locus,
					  problem > 1
					  ? DK_ERROR : DK_PERMERROR);
	      identified = 1;
	    }
	  if (complained)
	    {
	      if (problem > 1)
		inform (DECL_SOURCE_LOCATION (new_decls),
			"  crosses initialization of %q#D", new_decls);
	      else
		inform (DECL_SOURCE_LOCATION (new_decls),
			"  enters scope of %q#D, which has "
			"non-trivial destructor", new_decls);
	    }
	}

      if (b == level)
	break;

      const char *inf = NULL;
      location_t loc = input_location;
      switch (b->kind)
	{
	case sk_try:
	  if (!saw_eh)
	    inf = G_("  enters %<try%> block");
	  saw_eh = true;
	  break;

	case sk_catch:
	  if (!saw_eh)
	    inf = G_("  enters %<catch%> block");
	  saw_eh = true;
	  break;

	case sk_omp:
	  if (!saw_omp)
	    inf = G_("  enters OpenMP structured block");
	  saw_omp = true;
	  break;

	case sk_transaction:
	  if (!saw_tm)
	    inf = G_("  enters synchronized or atomic statement");
	  saw_tm = true;
	  break;

	case sk_block:
	  if (!saw_cxif && level_for_constexpr_if (b->level_chain))
	    {
	      inf = G_("  enters %<constexpr if%> statement");
	      loc = EXPR_LOCATION (b->level_chain->this_entity);
	      saw_cxif = true;
	    }
	  else if (!saw_ceif && level_for_consteval_if (b->level_chain))
	    {
	      inf = G_("  enters %<consteval if%> statement");
	      loc = EXPR_LOCATION (b->level_chain->this_entity);
	      saw_ceif = true;
	    }
	  break;

	default:
	  break;
	}

      if (inf)
	{
	  if (identified < 2)
	    complained = identify_goto (decl, input_location, locus, DK_ERROR);
	  identified = 2;
	  if (complained)
	    inform (loc, inf);
	}
    }

  return !identified;
}

static void
check_previous_goto (tree decl, struct named_label_use_entry *use)
{
  check_previous_goto_1 (decl, use->binding_level,
			 use->names_in_scope, use->in_omp_scope,
			 &use->o_goto_locus);
}

static bool
check_switch_goto (cp_binding_level* level)
{
  return check_previous_goto_1 (NULL_TREE, level, level->names, false, NULL);
}

/* Check that a new jump to a label DECL is OK.  Called by
   finish_goto_stmt.  */

void
check_goto (tree decl)
{
  /* We can't know where a computed goto is jumping.
     So we assume that it's OK.  */
  if (TREE_CODE (decl) != LABEL_DECL)
    return;

  /* We didn't record any information about this label when we created it,
     and there's not much point since it's trivial to analyze as a return.  */
  if (decl == cdtor_label)
    return;

  hashval_t hash = IDENTIFIER_HASH_VALUE (DECL_NAME (decl));
  named_label_entry **slot
    = named_labels->find_slot_with_hash (DECL_NAME (decl), hash, NO_INSERT);
  named_label_entry *ent = *slot;

  /* If the label hasn't been defined yet, defer checking.  */
  if (! DECL_INITIAL (decl))
    {
      /* Don't bother creating another use if the last goto had the
	 same data, and will therefore create the same set of errors.  */
      if (ent->uses
	  && ent->uses->names_in_scope == current_binding_level->names)
	return;

      named_label_use_entry *new_use
	= ggc_alloc<named_label_use_entry> ();
      new_use->binding_level = current_binding_level;
      new_use->names_in_scope = current_binding_level->names;
      new_use->o_goto_locus = input_location;
      new_use->in_omp_scope = false;

      new_use->next = ent->uses;
      ent->uses = new_use;
      return;
    }

  cp_function_chain->backward_goto = true;

  bool saw_catch = false, complained = false;
  int identified = 0;
  tree bad;
  unsigned ix;

  if (ent->in_try_scope || ent->in_catch_scope || ent->in_transaction_scope
      || ent->in_constexpr_if || ent->in_consteval_if
      || ent->in_omp_scope || !vec_safe_is_empty (ent->bad_decls))
    {
      diagnostic_t diag_kind = DK_PERMERROR;
      if (ent->in_try_scope || ent->in_catch_scope || ent->in_constexpr_if
	  || ent->in_consteval_if || ent->in_transaction_scope
	  || ent->in_omp_scope)
	diag_kind = DK_ERROR;
      complained = identify_goto (decl, DECL_SOURCE_LOCATION (decl),
				  &input_location, diag_kind);
      identified = 1 + (diag_kind == DK_ERROR);
    }

  FOR_EACH_VEC_SAFE_ELT (ent->bad_decls, ix, bad)
    {
      int u = decl_jump_unsafe (bad);

      if (u > 1 && DECL_ARTIFICIAL (bad))
	{
	  /* Can't skip init of __exception_info.  */
	  if (identified == 1)
	    {
	      complained = identify_goto (decl, DECL_SOURCE_LOCATION (decl),
					  &input_location, DK_ERROR);
	      identified = 2;
	    }
	  if (complained)
	    inform (DECL_SOURCE_LOCATION (bad), "  enters %<catch%> block");
	  saw_catch = true;
	}
      else if (complained)
	{
	  if (u > 1)
	    inform (DECL_SOURCE_LOCATION (bad),
		    "  skips initialization of %q#D", bad);
	  else
	    inform (DECL_SOURCE_LOCATION (bad),
		    "  enters scope of %q#D which has "
		    "non-trivial destructor", bad);
	}
    }

  if (complained)
    {
      if (ent->in_try_scope)
	inform (input_location, "  enters %<try%> block");
      else if (ent->in_catch_scope && !saw_catch)
	inform (input_location, "  enters %<catch%> block");
      else if (ent->in_transaction_scope)
	inform (input_location, "  enters synchronized or atomic statement");
      else if (ent->in_constexpr_if)
	inform (input_location, "  enters %<constexpr if%> statement");
      else if (ent->in_consteval_if)
	inform (input_location, "  enters %<consteval if%> statement");
    }

  if (ent->in_omp_scope)
    {
      if (complained)
	inform (input_location, "  enters OpenMP structured block");
    }
  else if (flag_openmp)
    for (cp_binding_level *b = current_binding_level; b ; b = b->level_chain)
      {
	if (b == ent->binding_level)
	  break;
	if (b->kind == sk_omp)
	  {
	    if (identified < 2)
	      {
		complained = identify_goto (decl,
					    DECL_SOURCE_LOCATION (decl),
					    &input_location, DK_ERROR);
		identified = 2;
	      }
	    if (complained)
	      inform (input_location, "  exits OpenMP structured block");
	    break;
	  }
      }
}

/* Check that a return is ok wrt OpenMP structured blocks.
   Called by finish_return_stmt.  Returns true if all is well.  */

bool
check_omp_return (void)
{
  for (cp_binding_level *b = current_binding_level; b ; b = b->level_chain)
    if (b->kind == sk_omp)
      {
	error ("invalid exit from OpenMP structured block");
	return false;
      }
    else if (b->kind == sk_function_parms)
      break;
  return true;
}

/* Define a label, specifying the location in the source file.
   Return the LABEL_DECL node for the label.  */

tree
define_label (location_t location, tree name)
{
  auto_cond_timevar tv (TV_NAME_LOOKUP);

  /* After labels, make any new cleanups in the function go into their
     own new (temporary) binding contour.  */
  for (cp_binding_level *p = current_binding_level;
       p->kind != sk_function_parms;
       p = p->level_chain)
    p->more_cleanups_ok = 0;

  named_label_entry *ent = lookup_label_1 (name, false);
  tree decl = ent->label_decl;

  if (DECL_INITIAL (decl) != NULL_TREE)
    {
      error ("duplicate label %qD", decl);
      return error_mark_node;
    }
  else
    {
      /* Mark label as having been defined.  */
      DECL_INITIAL (decl) = error_mark_node;
      /* Say where in the source.  */
      DECL_SOURCE_LOCATION (decl) = location;

      ent->binding_level = current_binding_level;
      ent->names_in_scope = current_binding_level->names;

      for (named_label_use_entry *use = ent->uses; use; use = use->next)
	check_previous_goto (decl, use);
      ent->uses = NULL;
    }

  return decl;
}

struct cp_switch
{
  cp_binding_level *level;
  struct cp_switch *next;
  /* The SWITCH_STMT being built.  */
  tree switch_stmt;
  /* A splay-tree mapping the low element of a case range to the high
     element, or NULL_TREE if there is no high element.  Used to
     determine whether or not a new case label duplicates an old case
     label.  We need a tree, rather than simply a hash table, because
     of the GNU case range extension.  */
  splay_tree cases;
  /* Remember whether a default: case label has been seen.  */
  bool has_default_p;
  /* Remember whether a BREAK_STMT has been seen in this SWITCH_STMT.  */
  bool break_stmt_seen_p;
  /* Set if inside of {FOR,DO,WHILE}_BODY nested inside of a switch,
     where BREAK_STMT doesn't belong to the SWITCH_STMT.  */
  bool in_loop_body_p;
};

/* A stack of the currently active switch statements.  The innermost
   switch statement is on the top of the stack.  There is no need to
   mark the stack for garbage collection because it is only active
   during the processing of the body of a function, and we never
   collect at that point.  */

static struct cp_switch *switch_stack;

/* Called right after a switch-statement condition is parsed.
   SWITCH_STMT is the switch statement being parsed.  */

void
push_switch (tree switch_stmt)
{
  struct cp_switch *p = XNEW (struct cp_switch);
  p->level = current_binding_level;
  p->next = switch_stack;
  p->switch_stmt = switch_stmt;
  p->cases = splay_tree_new (case_compare, NULL, NULL);
  p->has_default_p = false;
  p->break_stmt_seen_p = false;
  p->in_loop_body_p = false;
  switch_stack = p;
}

void
pop_switch (void)
{
  struct cp_switch *cs = switch_stack;

  /* Emit warnings as needed.  */
  location_t switch_location = cp_expr_loc_or_input_loc (cs->switch_stmt);
  tree cond = SWITCH_STMT_COND (cs->switch_stmt);
  const bool bool_cond_p
    = (SWITCH_STMT_TYPE (cs->switch_stmt)
       && TREE_CODE (SWITCH_STMT_TYPE (cs->switch_stmt)) == BOOLEAN_TYPE);
  if (!processing_template_decl)
    c_do_switch_warnings (cs->cases, switch_location,
			  SWITCH_STMT_TYPE (cs->switch_stmt), cond,
			  bool_cond_p);

  /* For the benefit of block_may_fallthru remember if the switch body
     case labels cover all possible values and if there are break; stmts.  */
  if (cs->has_default_p
      || (!processing_template_decl
	  && c_switch_covers_all_cases_p (cs->cases,
					  SWITCH_STMT_TYPE (cs->switch_stmt))))
    SWITCH_STMT_ALL_CASES_P (cs->switch_stmt) = 1;
  if (!cs->break_stmt_seen_p)
    SWITCH_STMT_NO_BREAK_P (cs->switch_stmt) = 1;
  /* Now that we're done with the switch warnings, set the switch type
     to the type of the condition if the index type was of scoped enum type.
     (Such types don't participate in the integer promotions.)  We do this
     because of bit-fields whose declared type is a scoped enum type:
     gimplification will use the lowered index type, but convert the
     case values to SWITCH_STMT_TYPE, which would have been the declared type
     and verify_gimple_switch doesn't accept that.  */
  if (is_bitfield_expr_with_lowered_type (cond))
    SWITCH_STMT_TYPE (cs->switch_stmt) = TREE_TYPE (cond);
  gcc_assert (!cs->in_loop_body_p);
  splay_tree_delete (cs->cases);
  switch_stack = switch_stack->next;
  free (cs);
}

/* Note that a BREAK_STMT is about to be added.  If it is inside of
   a SWITCH_STMT and not inside of a loop body inside of it, note
   in switch_stack we've seen a BREAK_STMT.  */

void
note_break_stmt (void)
{
  if (switch_stack && !switch_stack->in_loop_body_p)
    switch_stack->break_stmt_seen_p = true;
}

/* Note the start of processing of an iteration statement's body.
   The note_break_stmt function will do nothing while processing it.
   Return a flag that should be passed to note_iteration_stmt_body_end.  */

bool
note_iteration_stmt_body_start (void)
{
  if (!switch_stack)
    return false;
  bool ret = switch_stack->in_loop_body_p;
  switch_stack->in_loop_body_p = true;
  return ret;
}

/* Note the end of processing of an iteration statement's body.  */

void
note_iteration_stmt_body_end (bool prev)
{
  if (switch_stack)
    switch_stack->in_loop_body_p = prev;
}

/* Convert a case constant VALUE in a switch to the type TYPE of the switch
   condition.  Note that if TYPE and VALUE are already integral we don't
   really do the conversion because the language-independent
   warning/optimization code will work better that way.  */

static tree
case_conversion (tree type, tree value)
{
  if (value == NULL_TREE)
    return value;

  value = mark_rvalue_use (value);

  if (INTEGRAL_OR_UNSCOPED_ENUMERATION_TYPE_P (type))
    type = type_promotes_to (type);

  tree ovalue = value;
  /* The constant-expression VALUE shall be a converted constant expression
     of the adjusted type of the switch condition, which doesn't allow
     narrowing conversions.  */
  value = build_converted_constant_expr (type, value, tf_warning_or_error);

  if (cxx_dialect >= cxx11
      && (SCOPED_ENUM_P (type)
	  || !INTEGRAL_OR_UNSCOPED_ENUMERATION_TYPE_P (TREE_TYPE (ovalue))))
    /* Use the converted value.  */;
  else
    /* The already integral case.  */
    value = ovalue;

  return cxx_constant_value (value);
}

/* Note that we've seen a definition of a case label, and complain if this
   is a bad place for one.  */

tree
finish_case_label (location_t loc, tree low_value, tree high_value)
{
  tree cond, r;
  cp_binding_level *p;
  tree type;

  if (low_value == NULL_TREE && high_value == NULL_TREE)
    switch_stack->has_default_p = true;

  if (processing_template_decl)
    {
      tree label;

      /* For templates, just add the case label; we'll do semantic
	 analysis at instantiation-time.  */
      label = build_decl (loc, LABEL_DECL, NULL_TREE, void_type_node);
      return add_stmt (build_case_label (low_value, high_value, label));
    }

  /* Find the condition on which this switch statement depends.  */
  cond = SWITCH_STMT_COND (switch_stack->switch_stmt);
  if (cond && TREE_CODE (cond) == TREE_LIST)
    cond = TREE_VALUE (cond);

  if (!check_switch_goto (switch_stack->level))
    return error_mark_node;

  type = SWITCH_STMT_TYPE (switch_stack->switch_stmt);
  if (type == error_mark_node)
    return error_mark_node;

  low_value = case_conversion (type, low_value);
  high_value = case_conversion (type, high_value);

  r = c_add_case_label (loc, switch_stack->cases, cond, low_value, high_value);

  /* After labels, make any new cleanups in the function go into their
     own new (temporary) binding contour.  */
  for (p = current_binding_level;
       p->kind != sk_function_parms;
       p = p->level_chain)
    p->more_cleanups_ok = 0;

  return r;
}

struct typename_info {
  tree scope;
  tree name;
  tree template_id;
  bool enum_p;
  bool class_p;
};

struct typename_hasher : ggc_ptr_hash<tree_node>
{
  typedef typename_info *compare_type;

  /* Hash a TYPENAME_TYPE.  */

  static hashval_t
  hash (tree t)
  {
    hashval_t hash;

    hash = (htab_hash_pointer (TYPE_CONTEXT (t))
	    ^ htab_hash_pointer (TYPE_IDENTIFIER (t)));

    return hash;
  }

  /* Compare two TYPENAME_TYPEs.  */

  static bool
  equal (tree t1, const typename_info *t2)
  {
    return (TYPE_IDENTIFIER (t1) == t2->name
	    && TYPE_CONTEXT (t1) == t2->scope
	    && TYPENAME_TYPE_FULLNAME (t1) == t2->template_id
	    && TYPENAME_IS_ENUM_P (t1) == t2->enum_p
	    && TYPENAME_IS_CLASS_P (t1) == t2->class_p);
  }
};

/* Build a TYPENAME_TYPE.  If the type is `typename T::t', CONTEXT is
   the type of `T', NAME is the IDENTIFIER_NODE for `t'.

   Returns the new TYPENAME_TYPE.  */

static GTY (()) hash_table<typename_hasher> *typename_htab;

tree
build_typename_type (tree context, tree name, tree fullname,
		     enum tag_types tag_type)
{
  typename_info ti;

  if (typename_htab == NULL)
    typename_htab = hash_table<typename_hasher>::create_ggc (61);

  ti.scope = FROB_CONTEXT (context);
  ti.name = name;
  ti.template_id = fullname;
  ti.enum_p = tag_type == enum_type;
  ti.class_p = (tag_type == class_type
		|| tag_type == record_type
		|| tag_type == union_type);
  hashval_t hash =  (htab_hash_pointer (ti.scope)
		     ^ htab_hash_pointer (ti.name));

  /* See if we already have this type.  */
  tree *e = typename_htab->find_slot_with_hash (&ti, hash, INSERT);
  tree t = *e;
  if (*e)
    t = *e;
  else
    {
      /* Build the TYPENAME_TYPE.  */
      t = cxx_make_type (TYPENAME_TYPE);
      TYPE_CONTEXT (t) = ti.scope;
      TYPENAME_TYPE_FULLNAME (t) = ti.template_id;
      TYPENAME_IS_ENUM_P (t) = ti.enum_p;
      TYPENAME_IS_CLASS_P (t) = ti.class_p;

      /* Build the corresponding TYPE_DECL.  */
      tree d = build_decl (input_location, TYPE_DECL, name, t);
      TYPE_NAME (t) = d;
      TYPE_STUB_DECL (t) = d;
      DECL_CONTEXT (d) = ti.scope;
      DECL_ARTIFICIAL (d) = 1;

      /* Store it in the hash table.  */
      *e = t;

      /* TYPENAME_TYPEs must always be compared structurally, because
	 they may or may not resolve down to another type depending on
	 the currently open classes. */
      SET_TYPE_STRUCTURAL_EQUALITY (t);
    }

  return t;
}

/* Resolve `typename CONTEXT::NAME'.  TAG_TYPE indicates the tag
   provided to name the type.  Returns an appropriate type, unless an
   error occurs, in which case error_mark_node is returned.  If we
   locate a non-artificial TYPE_DECL and TF_KEEP_TYPE_DECL is set, we
   return that, rather than the _TYPE it corresponds to, in other
   cases we look through the type decl.  If TF_ERROR is set, complain
   about errors, otherwise be quiet.  */

tree
make_typename_type (tree context, tree name, enum tag_types tag_type,
		    tsubst_flags_t complain)
{
  tree fullname;
  tree t;
  bool want_template;

  if (name == error_mark_node
      || context == NULL_TREE
      || context == error_mark_node)
    return error_mark_node;

  if (TYPE_P (name))
    {
      if (!(TYPE_LANG_SPECIFIC (name)
	    && (CLASSTYPE_IS_TEMPLATE (name)
		|| CLASSTYPE_USE_TEMPLATE (name))))
	name = TYPE_IDENTIFIER (name);
      else
	/* Create a TEMPLATE_ID_EXPR for the type.  */
	name = build_nt (TEMPLATE_ID_EXPR,
			 CLASSTYPE_TI_TEMPLATE (name),
			 CLASSTYPE_TI_ARGS (name));
    }
  else if (TREE_CODE (name) == TYPE_DECL)
    name = DECL_NAME (name);

  fullname = name;

  if (TREE_CODE (name) == TEMPLATE_ID_EXPR)
    {
      name = TREE_OPERAND (name, 0);
      if (DECL_TYPE_TEMPLATE_P (name))
	name = TREE_OPERAND (fullname, 0) = DECL_NAME (name);
      if (TREE_CODE (name) != IDENTIFIER_NODE)
	{
	  if (complain & tf_error)
	    error ("%qD is not a type", name);
	  return error_mark_node;
	}
    }
  if (TREE_CODE (name) == TEMPLATE_DECL)
    {
      if (complain & tf_error)
	error ("%qD used without template arguments", name);
      return error_mark_node;
    }
  else if (is_overloaded_fn (name))
    {
      if (complain & tf_error)
	error ("%qD is a function, not a type", name);
      return error_mark_node;
    }
  gcc_assert (identifier_p (name));
  gcc_assert (TYPE_P (context));

  if (TREE_CODE (context) == TYPE_PACK_EXPANSION)
    /* This can happen for C++17 variadic using (c++/88986).  */;
  else if (!MAYBE_CLASS_TYPE_P (context))
    {
      if (complain & tf_error)
	error ("%q#T is not a class", context);
      return error_mark_node;
    }

  /* When the CONTEXT is a dependent type,  NAME could refer to a
     dependent base class of CONTEXT.  But look inside it anyway
     if CONTEXT is a currently open scope, in case it refers to a
     member of the current instantiation or a non-dependent base;
     lookup will stop when we hit a dependent base.  */
  if (!dependent_scope_p (context))
    /* We should only set WANT_TYPE when we're a nested typename type.
       Then we can give better diagnostics if we find a non-type.  */
    t = lookup_field (context, name, 2, /*want_type=*/true);
  else
    t = NULL_TREE;

  if ((!t || TREE_CODE (t) == TREE_LIST) && dependent_type_p (context))
    return build_typename_type (context, name, fullname, tag_type);

  want_template = TREE_CODE (fullname) == TEMPLATE_ID_EXPR;
  
  if (!t)
    {
      if (complain & tf_error)
	{
	  if (!COMPLETE_TYPE_P (context))
	    cxx_incomplete_type_error (NULL_TREE, context);
	  else
	    error (want_template ? G_("no class template named %q#T in %q#T")
		   : G_("no type named %q#T in %q#T"), name, context);
	}
      return error_mark_node;
    }
  
  /* Pull out the template from an injected-class-name (or multiple).  */
  if (want_template)
    t = maybe_get_template_decl_from_type_decl (t);

  if (TREE_CODE (t) == TREE_LIST)
    {
      if (complain & tf_error)
	{
	  error ("lookup of %qT in %qT is ambiguous", name, context);
	  print_candidates (t);
	}
      return error_mark_node;
    }

  if (want_template && !DECL_TYPE_TEMPLATE_P (t))
    {
      if (complain & tf_error)
	error ("%<typename %T::%D%> names %q#T, which is not a class template",
	       context, name, t);
      return error_mark_node;
    }
  if (!want_template && TREE_CODE (t) != TYPE_DECL)
    {
      if ((complain & tf_tst_ok) && cxx_dialect >= cxx17
	  && DECL_TYPE_TEMPLATE_P (t))
	/* The caller permits this typename-specifier to name a template
	   (because it appears in a CTAD-enabled context).  */;
      else
	{
	  if (complain & tf_error)
	    error ("%<typename %T::%D%> names %q#T, which is not a type",
		   context, name, t);
	  return error_mark_node;
	}
    }

  if (!check_accessibility_of_qualified_id (t, /*object_type=*/NULL_TREE,
					    context, complain))
    return error_mark_node;

  if (!want_template && DECL_TYPE_TEMPLATE_P (t))
    return make_template_placeholder (t);

  if (want_template)
    {
      t = lookup_template_class (t, TREE_OPERAND (fullname, 1),
				 NULL_TREE, context,
				 /*entering_scope=*/0,
				 complain | tf_user);
      if (t == error_mark_node)
	return error_mark_node;
      t = TYPE_NAME (t);
    }
  
  if (DECL_ARTIFICIAL (t) || !(complain & tf_keep_type_decl))
    t = TREE_TYPE (t);

  maybe_record_typedef_use (t);

  return t;
}

/* Resolve `CONTEXT::template NAME'.  Returns a TEMPLATE_DECL if the name
   can be resolved or an UNBOUND_CLASS_TEMPLATE, unless an error occurs,
   in which case error_mark_node is returned.

   If PARM_LIST is non-NULL, also make sure that the template parameter
   list of TEMPLATE_DECL matches.

   If COMPLAIN zero, don't complain about any errors that occur.  */

tree
make_unbound_class_template (tree context, tree name, tree parm_list,
			     tsubst_flags_t complain)
{
  if (TYPE_P (name))
    name = TYPE_IDENTIFIER (name);
  else if (DECL_P (name))
    name = DECL_NAME (name);
  gcc_assert (identifier_p (name));

  if (!dependent_type_p (context)
      || currently_open_class (context))
    {
      tree tmpl = NULL_TREE;

      if (MAYBE_CLASS_TYPE_P (context))
	tmpl = lookup_field (context, name, 0, false);

      if (tmpl && TREE_CODE (tmpl) == TYPE_DECL)
	tmpl = maybe_get_template_decl_from_type_decl (tmpl);

      if (!tmpl || !DECL_TYPE_TEMPLATE_P (tmpl))
	{
	  if (complain & tf_error)
	    error ("no class template named %q#T in %q#T", name, context);
	  return error_mark_node;
	}

      if (parm_list
	  && !comp_template_parms (DECL_TEMPLATE_PARMS (tmpl), parm_list))
	{
	  if (complain & tf_error)
	    {
	      error ("template parameters do not match template %qD", tmpl);
	      inform (DECL_SOURCE_LOCATION (tmpl),
		      "%qD declared here", tmpl);
	    }
	  return error_mark_node;
	}

      if (!perform_or_defer_access_check (TYPE_BINFO (context), tmpl, tmpl,
					  complain))
	return error_mark_node;

      return tmpl;
    }

  return make_unbound_class_template_raw (context, name, parm_list);
}

/* Build an UNBOUND_CLASS_TEMPLATE.  */

tree
make_unbound_class_template_raw (tree context, tree name, tree parm_list)
{
  /* Build the UNBOUND_CLASS_TEMPLATE.  */
  tree t = cxx_make_type (UNBOUND_CLASS_TEMPLATE);
  TYPE_CONTEXT (t) = FROB_CONTEXT (context);
  TREE_TYPE (t) = NULL_TREE;
  SET_TYPE_STRUCTURAL_EQUALITY (t);

  /* Build the corresponding TEMPLATE_DECL.  */
  tree d = build_decl (input_location, TEMPLATE_DECL, name, t);
  TYPE_NAME (t) = d;
  TYPE_STUB_DECL (t) = d;
  DECL_CONTEXT (d) = TYPE_CONTEXT (t);
  DECL_ARTIFICIAL (d) = 1;
  DECL_TEMPLATE_PARMS (d) = parm_list;

  return t;
}



/* Push the declarations of builtin types into the global namespace.
   RID_INDEX is the index of the builtin type in the array
   RID_POINTERS.  NAME is the name used when looking up the builtin
   type.  TYPE is the _TYPE node for the builtin type.

   The calls to set_global_binding below should be
   eliminated.  Built-in types should not be looked up name; their
   names are keywords that the parser can recognize.  However, there
   is code in c-common.cc that uses identifier_global_value to look up
   built-in types by name.  */

void
record_builtin_type (enum rid rid_index,
		     const char* name,
		     tree type)
{
  tree decl = NULL_TREE;

  if (name)
    {
      tree tname = get_identifier (name);
      tree tdecl = build_decl (BUILTINS_LOCATION, TYPE_DECL, tname, type);
      DECL_ARTIFICIAL (tdecl) = 1;
      set_global_binding (tdecl);
      decl = tdecl;
    }

  if ((int) rid_index < (int) RID_MAX)
    if (tree rname = ridpointers[(int) rid_index])
      if (!decl || DECL_NAME (decl) != rname)
	{
	  tree rdecl = build_decl (BUILTINS_LOCATION, TYPE_DECL, rname, type);
	  DECL_ARTIFICIAL (rdecl) = 1;
	  set_global_binding (rdecl);
	  if (!decl)
	    decl = rdecl;
	}

  if (decl)
    {
      if (!TYPE_NAME (type))
	TYPE_NAME (type) = decl;
      debug_hooks->type_decl (decl, 0);
    }
}

/* Push a type into the namespace so that the back ends ignore it.  */

static void
record_unknown_type (tree type, const char* name)
{
  tree decl = pushdecl (build_decl (UNKNOWN_LOCATION,
				    TYPE_DECL, get_identifier (name), type));
  /* Make sure the "unknown type" typedecl gets ignored for debug info.  */
  DECL_IGNORED_P (decl) = 1;
  TYPE_DECL_SUPPRESS_DEBUG (decl) = 1;
  TYPE_SIZE (type) = TYPE_SIZE (void_type_node);
  SET_TYPE_ALIGN (type, 1);
  TYPE_USER_ALIGN (type) = 0;
  SET_TYPE_MODE (type, TYPE_MODE (void_type_node));
}

/* Create all the predefined identifiers.  */

static void
initialize_predefined_identifiers (void)
{
  struct predefined_identifier
  {
    const char *name; /* Name.  */
    tree *node;  /* Node to store it in.  */
    cp_identifier_kind kind;  /* Kind of identifier.  */
  };

  /* A table of identifiers to create at startup.  */
  static const predefined_identifier predefined_identifiers[] = {
    {"C++", &lang_name_cplusplus, cik_normal},
    {"C", &lang_name_c, cik_normal},
    /* Some of these names have a trailing space so that it is
       impossible for them to conflict with names written by users.  */
    {"__ct ", &ctor_identifier, cik_ctor},
    {"__ct_base ", &base_ctor_identifier, cik_ctor},
    {"__ct_comp ", &complete_ctor_identifier, cik_ctor},
    {"__dt ", &dtor_identifier, cik_dtor},
    {"__dt_base ", &base_dtor_identifier, cik_dtor},
    {"__dt_comp ", &complete_dtor_identifier, cik_dtor},
    {"__dt_del ", &deleting_dtor_identifier, cik_dtor},
    {"__conv_op ", &conv_op_identifier, cik_conv_op},
    {"__in_chrg", &in_charge_identifier, cik_normal},
    {"__as_base ", &as_base_identifier, cik_normal},
    {"this", &this_identifier, cik_normal},
    {"__delta", &delta_identifier, cik_normal},
    {"__pfn", &pfn_identifier, cik_normal},
    {"_vptr", &vptr_identifier, cik_normal},
    {"__vtt_parm", &vtt_parm_identifier, cik_normal},
    {"::", &global_identifier, cik_normal},
      /* The demangler expects anonymous namespaces to be called
	 something starting with '_GLOBAL__N_'.  It no longer needs
	 to be unique to the TU.  */
    {"_GLOBAL__N_1", &anon_identifier, cik_normal},
    {"auto", &auto_identifier, cik_normal},
    {"decltype(auto)", &decltype_auto_identifier, cik_normal},
    {"initializer_list", &init_list_identifier, cik_normal},
    {"__for_range ", &for_range__identifier, cik_normal},
    {"__for_begin ", &for_begin__identifier, cik_normal},
    {"__for_end ", &for_end__identifier, cik_normal},
    {"__for_range", &for_range_identifier, cik_normal},
    {"__for_begin", &for_begin_identifier, cik_normal},
    {"__for_end", &for_end_identifier, cik_normal},
    {"abi_tag", &abi_tag_identifier, cik_normal},
    {"aligned", &aligned_identifier, cik_normal},
    {"begin", &begin_identifier, cik_normal},
    {"end", &end_identifier, cik_normal},
    {"get", &get__identifier, cik_normal},
    {"gnu", &gnu_identifier, cik_normal},
    {"tuple_element", &tuple_element_identifier, cik_normal},
    {"tuple_size", &tuple_size_identifier, cik_normal},
    {"type", &type_identifier, cik_normal},
    {"value", &value_identifier, cik_normal},
    {"_FUN", &fun_identifier, cik_normal},
    {"__closure", &closure_identifier, cik_normal},
    {"heap uninit", &heap_uninit_identifier, cik_normal},
    {"heap ", &heap_identifier, cik_normal},
    {"heap deleted", &heap_deleted_identifier, cik_normal},
    {"heap [] uninit", &heap_vec_uninit_identifier, cik_normal},
    {"heap []", &heap_vec_identifier, cik_normal},
    {"omp", &omp_identifier, cik_normal},
    {NULL, NULL, cik_normal}
  };

  for (const predefined_identifier *pid = predefined_identifiers;
       pid->name; ++pid)
    {
      *pid->node = get_identifier (pid->name);
      /* Some of these identifiers already have a special kind.  */
      if (pid->kind != cik_normal)
	set_identifier_kind (*pid->node, pid->kind);
    }
}

/* Create the predefined scalar types of C,
   and some nodes representing standard constants (0, 1, (void *)0).
   Initialize the global binding level.
   Make definitions for built-in primitive functions.  */

void
cxx_init_decl_processing (void)
{
  tree void_ftype;
  tree void_ftype_ptr;

  /* Create all the identifiers we need.  */
  initialize_predefined_identifiers ();

  /* Create the global variables.  */
  push_to_top_level ();

  current_function_decl = NULL_TREE;
  current_binding_level = NULL;
  /* Enter the global namespace.  */
  gcc_assert (global_namespace == NULL_TREE);
  global_namespace = build_lang_decl (NAMESPACE_DECL, global_identifier,
				      void_type_node);
  TREE_PUBLIC (global_namespace) = true;
  DECL_MODULE_EXPORT_P (global_namespace) = true;
  DECL_CONTEXT (global_namespace)
    = build_translation_unit_decl (get_identifier (main_input_filename));
  /* Remember whether we want the empty class passing ABI change warning
     in this TU.  */
  TRANSLATION_UNIT_WARN_EMPTY_P (DECL_CONTEXT (global_namespace))
    = warn_abi && abi_version_crosses (12);
  debug_hooks->register_main_translation_unit
    (DECL_CONTEXT (global_namespace));
  begin_scope (sk_namespace, global_namespace);
  current_namespace = global_namespace;

  if (flag_visibility_ms_compat)
    default_visibility = VISIBILITY_HIDDEN;

  /* Initially, C.  */
  current_lang_name = lang_name_c;

  /* Create the `std' namespace.  */
  push_namespace (get_identifier ("std"));
  std_node = current_namespace;
  pop_namespace ();

  flag_noexcept_type = (cxx_dialect >= cxx17);

  c_common_nodes_and_builtins ();

  tree bool_ftype = build_function_type_list (boolean_type_node, NULL_TREE);
  tree decl
    = add_builtin_function ("__builtin_is_constant_evaluated",
			    bool_ftype, CP_BUILT_IN_IS_CONSTANT_EVALUATED,
			    BUILT_IN_FRONTEND, NULL, NULL_TREE);
  set_call_expr_flags (decl, ECF_CONST | ECF_NOTHROW | ECF_LEAF);

  tree cptr_ftype = build_function_type_list (const_ptr_type_node, NULL_TREE);
  decl = add_builtin_function ("__builtin_source_location",
			       cptr_ftype, CP_BUILT_IN_SOURCE_LOCATION,
			       BUILT_IN_FRONTEND, NULL, NULL_TREE);
  set_call_expr_flags (decl, ECF_CONST | ECF_NOTHROW | ECF_LEAF);

  tree bool_vaftype = build_varargs_function_type_list (boolean_type_node,
							NULL_TREE);
  decl
    = add_builtin_function ("__builtin_is_corresponding_member",
			    bool_vaftype,
			    CP_BUILT_IN_IS_CORRESPONDING_MEMBER,
			    BUILT_IN_FRONTEND, NULL, NULL_TREE);
  set_call_expr_flags (decl, ECF_CONST | ECF_NOTHROW | ECF_LEAF);

  decl
    = add_builtin_function ("__builtin_is_pointer_interconvertible_with_class",
			    bool_vaftype,
			    CP_BUILT_IN_IS_POINTER_INTERCONVERTIBLE_WITH_CLASS,
			    BUILT_IN_FRONTEND, NULL, NULL_TREE);
  set_call_expr_flags (decl, ECF_CONST | ECF_NOTHROW | ECF_LEAF);

  integer_two_node = build_int_cst (NULL_TREE, 2);

  /* Guess at the initial static decls size.  */
  vec_alloc (static_decls, 500);

  /* ... and keyed classes.  */
  vec_alloc (keyed_classes, 100);

  record_builtin_type (RID_BOOL, "bool", boolean_type_node);
  truthvalue_type_node = boolean_type_node;
  truthvalue_false_node = boolean_false_node;
  truthvalue_true_node = boolean_true_node;

  empty_except_spec = build_tree_list (NULL_TREE, NULL_TREE);
  noexcept_true_spec = build_tree_list (boolean_true_node, NULL_TREE);
  noexcept_false_spec = build_tree_list (boolean_false_node, NULL_TREE);
  noexcept_deferred_spec = build_tree_list (make_node (DEFERRED_NOEXCEPT),
					    NULL_TREE);

#if 0
  record_builtin_type (RID_MAX, NULL, string_type_node);
#endif

  delta_type_node = ptrdiff_type_node;
  vtable_index_type = ptrdiff_type_node;

  vtt_parm_type = build_pointer_type (const_ptr_type_node);
  void_ftype = build_function_type_list (void_type_node, NULL_TREE);
  void_ftype_ptr = build_function_type_list (void_type_node,
					     ptr_type_node, NULL_TREE);
  void_ftype_ptr
    = build_exception_variant (void_ftype_ptr, empty_except_spec);

  /* Create the conversion operator marker.  This operator's DECL_NAME
     is in the identifier table, so we can use identifier equality to
     find it.  */
  conv_op_marker = build_lang_decl (FUNCTION_DECL, conv_op_identifier,
				    void_ftype);

  /* C++ extensions */

  unknown_type_node = make_node (LANG_TYPE);
  record_unknown_type (unknown_type_node, "unknown type");

  /* Indirecting an UNKNOWN_TYPE node yields an UNKNOWN_TYPE node.  */
  TREE_TYPE (unknown_type_node) = unknown_type_node;

  /* Looking up TYPE_POINTER_TO and TYPE_REFERENCE_TO yield the same
     result.  */
  TYPE_POINTER_TO (unknown_type_node) = unknown_type_node;
  TYPE_REFERENCE_TO (unknown_type_node) = unknown_type_node;

  init_list_type_node = make_node (LANG_TYPE);
  record_unknown_type (init_list_type_node, "init list");

  /* Used when parsing to distinguish parameter-lists () and (void).  */
  explicit_void_list_node = build_void_list_node ();

  {
    /* Make sure we get a unique function type, so we can give
       its pointer type a name.  (This wins for gdb.) */
    tree vfunc_type = make_node (FUNCTION_TYPE);
    TREE_TYPE (vfunc_type) = integer_type_node;
    TYPE_ARG_TYPES (vfunc_type) = NULL_TREE;
    layout_type (vfunc_type);

    vtable_entry_type = build_pointer_type (vfunc_type);
  }
  record_builtin_type (RID_MAX, "__vtbl_ptr_type", vtable_entry_type);

  vtbl_type_node
    = build_cplus_array_type (vtable_entry_type, NULL_TREE);
  layout_type (vtbl_type_node);
  vtbl_type_node = cp_build_qualified_type (vtbl_type_node, TYPE_QUAL_CONST);
  record_builtin_type (RID_MAX, NULL, vtbl_type_node);
  vtbl_ptr_type_node = build_pointer_type (vtable_entry_type);
  layout_type (vtbl_ptr_type_node);
  record_builtin_type (RID_MAX, NULL, vtbl_ptr_type_node);

  push_namespace (get_identifier ("__cxxabiv1"));
  abi_node = current_namespace;
  pop_namespace ();

  any_targ_node = make_node (LANG_TYPE);
  record_unknown_type (any_targ_node, "any type");

  /* Now, C++.  */
  current_lang_name = lang_name_cplusplus;

  if (aligned_new_threshold > 1
      && !pow2p_hwi (aligned_new_threshold))
    {
      error ("%<-faligned-new=%d%> is not a power of two",
	     aligned_new_threshold);
      aligned_new_threshold = 1;
    }
  if (aligned_new_threshold == -1)
    aligned_new_threshold = (cxx_dialect >= cxx17) ? 1 : 0;
  if (aligned_new_threshold == 1)
    aligned_new_threshold = malloc_alignment () / BITS_PER_UNIT;

  {
    tree newattrs, extvisattr;
    tree newtype, deltype;
    tree ptr_ftype_sizetype;
    tree new_eh_spec;

    ptr_ftype_sizetype
      = build_function_type_list (ptr_type_node, size_type_node, NULL_TREE);
    if (cxx_dialect == cxx98)
      {
	tree bad_alloc_id;
	tree bad_alloc_type_node;
	tree bad_alloc_decl;

	push_nested_namespace (std_node);
	bad_alloc_id = get_identifier ("bad_alloc");
	bad_alloc_type_node = make_class_type (RECORD_TYPE);
	TYPE_CONTEXT (bad_alloc_type_node) = current_namespace;
	bad_alloc_decl
	  = create_implicit_typedef (bad_alloc_id, bad_alloc_type_node);
	DECL_CONTEXT (bad_alloc_decl) = current_namespace;
	pop_nested_namespace (std_node);

	new_eh_spec
	  = add_exception_specifier (NULL_TREE, bad_alloc_type_node, -1);
      }
    else
      new_eh_spec = noexcept_false_spec;

    /* Ensure attribs.cc is initialized.  */
    init_attributes ();

    extvisattr = build_tree_list (get_identifier ("externally_visible"),
				  NULL_TREE);
    newattrs = tree_cons (get_identifier ("alloc_size"),
			  build_tree_list (NULL_TREE, integer_one_node),
			  extvisattr);
    newtype = cp_build_type_attribute_variant (ptr_ftype_sizetype, newattrs);
    newtype = build_exception_variant (newtype, new_eh_spec);
    deltype = cp_build_type_attribute_variant (void_ftype_ptr, extvisattr);
    deltype = build_exception_variant (deltype, empty_except_spec);
    tree opnew = push_cp_library_fn (NEW_EXPR, newtype, 0);
    DECL_IS_MALLOC (opnew) = 1;
    DECL_SET_IS_OPERATOR_NEW (opnew, true);
    DECL_IS_REPLACEABLE_OPERATOR (opnew) = 1;
    opnew = push_cp_library_fn (VEC_NEW_EXPR, newtype, 0);
    DECL_IS_MALLOC (opnew) = 1;
    DECL_SET_IS_OPERATOR_NEW (opnew, true);
    DECL_IS_REPLACEABLE_OPERATOR (opnew) = 1;
    tree opdel = push_cp_library_fn (DELETE_EXPR, deltype, ECF_NOTHROW);
    DECL_SET_IS_OPERATOR_DELETE (opdel, true);
    DECL_IS_REPLACEABLE_OPERATOR (opdel) = 1;
    opdel = push_cp_library_fn (VEC_DELETE_EXPR, deltype, ECF_NOTHROW);
    DECL_SET_IS_OPERATOR_DELETE (opdel, true);
    DECL_IS_REPLACEABLE_OPERATOR (opdel) = 1;
    if (flag_sized_deallocation)
      {
	/* Also push the sized deallocation variants:
	     void operator delete(void*, std::size_t) throw();
	     void operator delete[](void*, std::size_t) throw();  */
	tree void_ftype_ptr_size
	  = build_function_type_list (void_type_node, ptr_type_node,
				      size_type_node, NULL_TREE);
	deltype = cp_build_type_attribute_variant (void_ftype_ptr_size,
						   extvisattr);
	deltype = build_exception_variant (deltype, empty_except_spec);
	opdel = push_cp_library_fn (DELETE_EXPR, deltype, ECF_NOTHROW);
	DECL_SET_IS_OPERATOR_DELETE (opdel, true);
	DECL_IS_REPLACEABLE_OPERATOR (opdel) = 1;
	opdel = push_cp_library_fn (VEC_DELETE_EXPR, deltype, ECF_NOTHROW);
	DECL_SET_IS_OPERATOR_DELETE (opdel, true);
	DECL_IS_REPLACEABLE_OPERATOR (opdel) = 1;
      }

    if (aligned_new_threshold)
      {
	push_nested_namespace (std_node);
	tree align_id = get_identifier ("align_val_t");
	align_type_node = start_enum (align_id, NULL_TREE, size_type_node,
				      NULL_TREE, /*scoped*/true, NULL);
	pop_nested_namespace (std_node);

	/* operator new (size_t, align_val_t); */
	newtype = build_function_type_list (ptr_type_node, size_type_node,
					    align_type_node, NULL_TREE);
	newtype = cp_build_type_attribute_variant (newtype, newattrs);
	newtype = build_exception_variant (newtype, new_eh_spec);
	opnew = push_cp_library_fn (NEW_EXPR, newtype, 0);
	DECL_IS_MALLOC (opnew) = 1;
	DECL_SET_IS_OPERATOR_NEW (opnew, true);
	DECL_IS_REPLACEABLE_OPERATOR (opnew) = 1;
	opnew = push_cp_library_fn (VEC_NEW_EXPR, newtype, 0);
	DECL_IS_MALLOC (opnew) = 1;
	DECL_SET_IS_OPERATOR_NEW (opnew, true);
	DECL_IS_REPLACEABLE_OPERATOR (opnew) = 1;

	/* operator delete (void *, align_val_t); */
	deltype = build_function_type_list (void_type_node, ptr_type_node,
					    align_type_node, NULL_TREE);
	deltype = cp_build_type_attribute_variant (deltype, extvisattr);
	deltype = build_exception_variant (deltype, empty_except_spec);
	opdel = push_cp_library_fn (DELETE_EXPR, deltype, ECF_NOTHROW);
	DECL_SET_IS_OPERATOR_DELETE (opdel, true);
	DECL_IS_REPLACEABLE_OPERATOR (opdel) = 1;
	opdel = push_cp_library_fn (VEC_DELETE_EXPR, deltype, ECF_NOTHROW);
	DECL_SET_IS_OPERATOR_DELETE (opdel, true);
	DECL_IS_REPLACEABLE_OPERATOR (opdel) = 1;

	if (flag_sized_deallocation)
	  {
	    /* operator delete (void *, size_t, align_val_t); */
	    deltype = build_function_type_list (void_type_node, ptr_type_node,
						size_type_node, align_type_node,
						NULL_TREE);
	    deltype = cp_build_type_attribute_variant (deltype, extvisattr);
	    deltype = build_exception_variant (deltype, empty_except_spec);
	    opdel = push_cp_library_fn (DELETE_EXPR, deltype, ECF_NOTHROW);
	    DECL_SET_IS_OPERATOR_DELETE (opdel, true);
	    DECL_IS_REPLACEABLE_OPERATOR (opdel) = 1;
	    opdel = push_cp_library_fn (VEC_DELETE_EXPR, deltype, ECF_NOTHROW);
	    DECL_SET_IS_OPERATOR_DELETE (opdel, true);
	    DECL_IS_REPLACEABLE_OPERATOR (opdel) = 1;
	  }
      }

    nullptr_type_node = make_node (NULLPTR_TYPE);
    TYPE_SIZE (nullptr_type_node) = bitsize_int (GET_MODE_BITSIZE (ptr_mode));
    TYPE_SIZE_UNIT (nullptr_type_node) = size_int (GET_MODE_SIZE (ptr_mode));
    TYPE_UNSIGNED (nullptr_type_node) = 1;
    TYPE_PRECISION (nullptr_type_node) = GET_MODE_BITSIZE (ptr_mode);
    if (abi_version_at_least (9))
      SET_TYPE_ALIGN (nullptr_type_node, GET_MODE_ALIGNMENT (ptr_mode));
    SET_TYPE_MODE (nullptr_type_node, ptr_mode);
    record_builtin_type (RID_MAX, "decltype(nullptr)", nullptr_type_node);
    nullptr_node = build_int_cst (nullptr_type_node, 0);
  }

  if (! supports_one_only ())
    flag_weak = 0;

  abort_fndecl
    = build_library_fn_ptr ("__cxa_pure_virtual", void_ftype,
			    ECF_NORETURN | ECF_NOTHROW | ECF_COLD);
  if (flag_weak)
    /* If no definition is available, resolve references to NULL.  */
    declare_weak (abort_fndecl);

  /* Perform other language dependent initializations.  */
  init_class_processing ();
  init_rtti_processing ();
  init_template_processing ();

  if (flag_exceptions)
    init_exception_processing ();

  if (modules_p ())
    init_modules (parse_in);

  make_fname_decl = cp_make_fname_decl;
  start_fname_decls ();

  /* Show we use EH for cleanups.  */
  if (flag_exceptions)
    using_eh_for_cleanups ();

  /* Check that the hardware interference sizes are at least
     alignof(max_align_t), as required by the standard.  */
  const int max_align = max_align_t_align () / BITS_PER_UNIT;
  if (OPTION_SET_P (param_destruct_interfere_size))
    {
      if (param_destruct_interfere_size < max_align)
	error ("%<--param destructive-interference-size=%d%> is less than "
	       "%d", param_destruct_interfere_size, max_align);
      else if (param_destruct_interfere_size < param_l1_cache_line_size)
	warning (OPT_Winterference_size,
		 "%<--param destructive-interference-size=%d%> "
		 "is less than %<--param l1-cache-line-size=%d%>",
		 param_destruct_interfere_size, param_l1_cache_line_size);
    }
  else if (param_destruct_interfere_size)
    /* Assume the internal value is OK.  */;
  else if (param_l1_cache_line_size >= max_align)
    param_destruct_interfere_size = param_l1_cache_line_size;
  /* else leave it unset.  */

  if (OPTION_SET_P (param_construct_interfere_size))
    {
      if (param_construct_interfere_size < max_align)
	error ("%<--param constructive-interference-size=%d%> is less than "
	       "%d", param_construct_interfere_size, max_align);
      else if (param_construct_interfere_size > param_l1_cache_line_size
	       && param_l1_cache_line_size >= max_align)
	warning (OPT_Winterference_size,
		 "%<--param constructive-interference-size=%d%> "
		 "is greater than %<--param l1-cache-line-size=%d%>",
		 param_construct_interfere_size, param_l1_cache_line_size);
    }
  else if (param_construct_interfere_size)
    /* Assume the internal value is OK.  */;
  else if (param_l1_cache_line_size >= max_align)
    param_construct_interfere_size = param_l1_cache_line_size;
}

/* Enter an abi node in global-module context.  returns a cookie to
   give to pop_abi_namespace.  */

unsigned
push_abi_namespace (tree node)
{
  push_nested_namespace (node);
  push_visibility ("default", 2);
  unsigned flags = module_kind;
  module_kind = 0;
  return flags;
}

/* Pop an abi namespace, FLAGS is the cookie push_abi_namespace gave
   you.  */

void
pop_abi_namespace (unsigned flags, tree node)
{
  module_kind = flags;
  pop_visibility (2);
  pop_nested_namespace (node);
}

/* Create the VAR_DECL for __FUNCTION__ etc. ID is the name to give
   the decl, LOC is the location to give the decl, NAME is the
   initialization string and TYPE_DEP indicates whether NAME depended
   on the type of the function. We make use of that to detect
   __PRETTY_FUNCTION__ inside a template fn. This is being done lazily
   at the point of first use, so we mustn't push the decl now.  */

static tree
cp_make_fname_decl (location_t loc, tree id, int type_dep)
{
  tree domain = NULL_TREE;
  tree init = NULL_TREE;

  if (!(type_dep && in_template_function ()))
    {
      const char *name = NULL;
      bool release_name = false;

      if (current_function_decl == NULL_TREE)
	name = "top level";
      else if (type_dep == 0)
	{
	  /* __FUNCTION__ */	  
	  name = fname_as_string (type_dep);
	  release_name = true;
	}
      else
	{
	  /* __PRETTY_FUNCTION__ */
	  gcc_checking_assert (type_dep == 1);
	  name = cxx_printable_name (current_function_decl, 2);
	}

      size_t length = strlen (name);
      domain = build_index_type (size_int (length));
      init = build_string (length + 1, name);
      if (release_name)
	free (const_cast<char *> (name));
    }

  tree type = cp_build_qualified_type (char_type_node, TYPE_QUAL_CONST);
  type = build_cplus_array_type (type, domain);

  if (init)
    TREE_TYPE (init) = type;
  else
    init = error_mark_node;

  tree decl = build_decl (loc, VAR_DECL, id, type);

  TREE_READONLY (decl) = 1;
  DECL_ARTIFICIAL (decl) = 1;
  DECL_DECLARED_CONSTEXPR_P (decl) = 1;
  TREE_STATIC (decl) = 1;

  TREE_USED (decl) = 1;

  SET_DECL_VALUE_EXPR (decl, init);
  DECL_HAS_VALUE_EXPR_P (decl) = 1;
  /* For decl_constant_var_p.  */
  DECL_INITIALIZED_BY_CONSTANT_EXPRESSION_P (decl) = 1;

  if (current_function_decl)
    {
      DECL_CONTEXT (decl) = current_function_decl;
      decl = pushdecl_outermost_localscope (decl);
      if (decl != error_mark_node)
	add_decl_expr (decl);
    }
  else
    {
      DECL_THIS_STATIC (decl) = true;
      decl = pushdecl_top_level_and_finish (decl, NULL_TREE);
    }

  return decl;
}

/* Install DECL as a builtin function at current global scope.  Return
   the new decl (if we found an existing version).  Also installs it
   into ::std, if it's not '_*'.  */

tree
cxx_builtin_function (tree decl)
{
  retrofit_lang_decl (decl);

  DECL_ARTIFICIAL (decl) = 1;
  SET_DECL_LANGUAGE (decl, lang_c);
  /* Runtime library routines are, by definition, available in an
     external shared object.  */
  DECL_VISIBILITY (decl) = VISIBILITY_DEFAULT;
  DECL_VISIBILITY_SPECIFIED (decl) = 1;

  tree id = DECL_NAME (decl);
  const char *name = IDENTIFIER_POINTER (id);
  bool hiding = false;
  if (name[0] != '_' || name[1] != '_')
    /* In the user's namespace, it must be declared before use.  */
    hiding = true;
  else if (IDENTIFIER_LENGTH (id) > strlen ("___chk")
	   && !startswith (name + 2, "builtin_")
	   && 0 == memcmp (name + IDENTIFIER_LENGTH (id) - strlen ("_chk"),
			   "_chk", strlen ("_chk") + 1))
    /* Treat __*_chk fortification functions as anticipated as well,
       unless they are __builtin_*_chk.  */
    hiding = true;

  /* All builtins that don't begin with an '_' should additionally
     go in the 'std' namespace.  */
  if (name[0] != '_')
    {
      tree std_decl = copy_decl (decl);

      push_nested_namespace (std_node);
      DECL_CONTEXT (std_decl) = FROB_CONTEXT (std_node);
      pushdecl (std_decl, hiding);
      pop_nested_namespace (std_node);
    }

  DECL_CONTEXT (decl) = FROB_CONTEXT (current_namespace);
  decl = pushdecl (decl, hiding);

  return decl;
}

/* Like cxx_builtin_function, but guarantee the function is added to the global
   scope.  This is to allow function specific options to add new machine
   dependent builtins when the target ISA changes via attribute((target(...)))
   which saves space on program startup if the program does not use non-generic
   ISAs.  */

tree
cxx_builtin_function_ext_scope (tree decl)
{
  push_nested_namespace (global_namespace);
  decl = cxx_builtin_function (decl);
  pop_nested_namespace (global_namespace);

  return decl;
}

/* Implement LANG_HOOKS_SIMULATE_BUILTIN_FUNCTION_DECL.  */

tree
cxx_simulate_builtin_function_decl (tree decl)
{
  retrofit_lang_decl (decl);

  DECL_ARTIFICIAL (decl) = 1;
  SET_DECL_LANGUAGE (decl, lang_cplusplus);
  DECL_CONTEXT (decl) = FROB_CONTEXT (current_namespace);
  return pushdecl (decl);
}

/* Generate a FUNCTION_DECL with the typical flags for a runtime library
   function.  Not called directly.  */

static tree
build_library_fn (tree name, enum tree_code operator_code, tree type,
		  int ecf_flags)
{
  tree fn = build_lang_decl (FUNCTION_DECL, name, type);
  DECL_EXTERNAL (fn) = 1;
  TREE_PUBLIC (fn) = 1;
  DECL_ARTIFICIAL (fn) = 1;
  DECL_OVERLOADED_OPERATOR_CODE_RAW (fn)
    = OVL_OP_INFO (false, operator_code)->ovl_op_code;
  SET_DECL_LANGUAGE (fn, lang_c);
  /* Runtime library routines are, by definition, available in an
     external shared object.  */
  DECL_VISIBILITY (fn) = VISIBILITY_DEFAULT;
  DECL_VISIBILITY_SPECIFIED (fn) = 1;
  set_call_expr_flags (fn, ecf_flags);
  return fn;
}

/* Returns the _DECL for a library function with C++ linkage.  */

static tree
build_cp_library_fn (tree name, enum tree_code operator_code, tree type,
		     int ecf_flags)
{
  tree fn = build_library_fn (name, operator_code, type, ecf_flags);
  DECL_CONTEXT (fn) = FROB_CONTEXT (current_namespace);
  SET_DECL_LANGUAGE (fn, lang_cplusplus);
  return fn;
}

/* Like build_library_fn, but takes a C string instead of an
   IDENTIFIER_NODE.  */

tree
build_library_fn_ptr (const char* name, tree type, int ecf_flags)
{
  return build_library_fn (get_identifier (name), ERROR_MARK, type, ecf_flags);
}

/* Like build_cp_library_fn, but takes a C string instead of an
   IDENTIFIER_NODE.  */

tree
build_cp_library_fn_ptr (const char* name, tree type, int ecf_flags)
{
  return build_cp_library_fn (get_identifier (name), ERROR_MARK, type,
			      ecf_flags);
}

/* Like build_library_fn, but also pushes the function so that we will
   be able to find it via get_global_binding.  Also, the function
   may throw exceptions listed in RAISES.  */

tree
push_library_fn (tree name, tree type, tree raises, int ecf_flags)
{
  if (raises)
    type = build_exception_variant (type, raises);

  tree fn = build_library_fn (name, ERROR_MARK, type, ecf_flags);
  return pushdecl_top_level (fn);
}

/* Like build_cp_library_fn, but also pushes the function so that it
   will be found by normal lookup.  */

static tree
push_cp_library_fn (enum tree_code operator_code, tree type,
		    int ecf_flags)
{
  tree fn = build_cp_library_fn (ovl_op_identifier (false, operator_code),
				 operator_code, type, ecf_flags);
  pushdecl (fn);
  if (flag_tm)
    apply_tm_attr (fn, get_identifier ("transaction_safe"));
  return fn;
}

/* Like push_library_fn, but also note that this function throws
   and does not return.  Used for __throw_foo and the like.  */

tree
push_throw_library_fn (tree name, tree type)
{
  tree fn = push_library_fn (name, type, NULL_TREE, ECF_NORETURN | ECF_COLD);
  return fn;
}

/* When we call finish_struct for an anonymous union, we create
   default copy constructors and such.  But, an anonymous union
   shouldn't have such things; this function undoes the damage to the
   anonymous union type T.

   (The reason that we create the synthesized methods is that we don't
   distinguish `union { int i; }' from `typedef union { int i; } U'.
   The first is an anonymous union; the second is just an ordinary
   union type.)  */

void
fixup_anonymous_aggr (tree t)
{
  /* Wipe out memory of synthesized methods.  */
  TYPE_HAS_USER_CONSTRUCTOR (t) = 0;
  TYPE_HAS_DEFAULT_CONSTRUCTOR (t) = 0;
  TYPE_HAS_COPY_CTOR (t) = 0;
  TYPE_HAS_CONST_COPY_CTOR (t) = 0;
  TYPE_HAS_COPY_ASSIGN (t) = 0;
  TYPE_HAS_CONST_COPY_ASSIGN (t) = 0;

  /* Splice the implicitly generated functions out of TYPE_FIELDS and diagnose
     invalid members.  */
  for (tree probe, *prev_p = &TYPE_FIELDS (t); (probe = *prev_p);)
    {
      if (TREE_CODE (probe) == FUNCTION_DECL && DECL_ARTIFICIAL (probe))
	*prev_p = DECL_CHAIN (probe);
      else
	prev_p = &DECL_CHAIN (probe);

      if (DECL_ARTIFICIAL (probe)
	  && (!DECL_IMPLICIT_TYPEDEF_P (probe)
	      || TYPE_ANON_P (TREE_TYPE (probe))))
	continue;

      if (TREE_CODE (probe) != FIELD_DECL
	  || (TREE_PRIVATE (probe) || TREE_PROTECTED (probe)))
	{
	  /* We already complained about static data members in
	     finish_static_data_member_decl.  */
	  if (!VAR_P (probe))
	    {
	      auto_diagnostic_group d;
	      if (permerror (DECL_SOURCE_LOCATION (probe),
			     TREE_CODE (t) == UNION_TYPE
			     ? "%q#D invalid; an anonymous union may "
			     "only have public non-static data members"
			     : "%q#D invalid; an anonymous struct may "
			     "only have public non-static data members", probe))
		{
		  static bool hint;
		  if (flag_permissive && !hint)
		    {
		      hint = true;
		      inform (DECL_SOURCE_LOCATION (probe),
			      "this flexibility is deprecated and will be "
			      "removed");
		    }
		}
	    }
	}
      }

  /* Splice all functions out of CLASSTYPE_MEMBER_VEC.  */
  vec<tree,va_gc>* vec = CLASSTYPE_MEMBER_VEC (t);
  unsigned store = 0;
  for (tree elt : vec)
    if (!is_overloaded_fn (elt))
      (*vec)[store++] = elt;
  vec_safe_truncate (vec, store);

  /* Wipe RTTI info.  */
  CLASSTYPE_TYPEINFO_VAR (t) = NULL_TREE;

  /* Anonymous aggregates cannot have fields with ctors, dtors or complex
     assignment operators (because they cannot have these methods themselves).
     For anonymous unions this is already checked because they are not allowed
     in any union, otherwise we have to check it.  */
  if (TREE_CODE (t) != UNION_TYPE)
    {
      tree field, type;

      if (BINFO_N_BASE_BINFOS (TYPE_BINFO (t)))
	{
	  error_at (location_of (t), "anonymous struct with base classes");
	  /* Avoid ICE after error on anon-struct9.C.  */
	  TYPE_NEEDS_CONSTRUCTING (t) = false;
	}

      for (field = TYPE_FIELDS (t); field; field = DECL_CHAIN (field))
	if (TREE_CODE (field) == FIELD_DECL)
	  {
	    type = TREE_TYPE (field);
	    if (CLASS_TYPE_P (type))
	      {
		if (TYPE_NEEDS_CONSTRUCTING (type))
		  error ("member %q+#D with constructor not allowed "
			 "in anonymous aggregate", field);
		if (TYPE_HAS_NONTRIVIAL_DESTRUCTOR (type))
		  error ("member %q+#D with destructor not allowed "
			 "in anonymous aggregate", field);
		if (TYPE_HAS_COMPLEX_COPY_ASSIGN (type))
		  error ("member %q+#D with copy assignment operator "
			 "not allowed in anonymous aggregate", field);
	      }
	  }
    }
}

/* Warn for an attribute located at LOCATION that appertains to the
   class type CLASS_TYPE that has not been properly placed after its
   class-key, in it class-specifier.  */

void
warn_misplaced_attr_for_class_type (location_t location,
				    tree class_type)
{
  gcc_assert (OVERLOAD_TYPE_P (class_type));

  auto_diagnostic_group d;
  if (warning_at (location, OPT_Wattributes,
		  "attribute ignored in declaration "
		  "of %q#T", class_type))
    inform (location,
	    "attribute for %q#T must follow the %qs keyword",
	    class_type, class_key_or_enum_as_string (class_type));
}

/* Returns the cv-qualifiers that apply to the type specified
   by the DECLSPECS.  */

static int
get_type_quals (const cp_decl_specifier_seq *declspecs)
{
  int type_quals = TYPE_UNQUALIFIED;

  if (decl_spec_seq_has_spec_p (declspecs, ds_const))
    type_quals |= TYPE_QUAL_CONST;
  if (decl_spec_seq_has_spec_p (declspecs, ds_volatile))
    type_quals |= TYPE_QUAL_VOLATILE;
  if (decl_spec_seq_has_spec_p (declspecs, ds_restrict))
    type_quals |= TYPE_QUAL_RESTRICT;

  return type_quals;
}

/* Make sure that a declaration with no declarator is well-formed, i.e.
   just declares a tagged type or anonymous union.

   Returns the type declared; or NULL_TREE if none.  */

tree
check_tag_decl (cp_decl_specifier_seq *declspecs,
		bool explicit_type_instantiation_p)
{
  int saw_friend = decl_spec_seq_has_spec_p (declspecs, ds_friend);
  int saw_typedef = decl_spec_seq_has_spec_p (declspecs, ds_typedef);
  /* If a class, struct, or enum type is declared by the DECLSPECS
     (i.e, if a class-specifier, enum-specifier, or non-typename
     elaborated-type-specifier appears in the DECLSPECS),
     DECLARED_TYPE is set to the corresponding type.  */
  tree declared_type = NULL_TREE;
  bool error_p = false;

  if (declspecs->multiple_types_p)
    error_at (smallest_type_location (declspecs),
	      "multiple types in one declaration");
  else if (declspecs->redefined_builtin_type)
    {
      location_t loc = declspecs->locations[ds_redefined_builtin_type_spec];
      if (!in_system_header_at (loc))
	permerror (loc, "redeclaration of C++ built-in type %qT",
		   declspecs->redefined_builtin_type);
      return NULL_TREE;
    }

  if (declspecs->type
      && TYPE_P (declspecs->type)
      && ((TREE_CODE (declspecs->type) != TYPENAME_TYPE
	   && MAYBE_CLASS_TYPE_P (declspecs->type))
	  || TREE_CODE (declspecs->type) == ENUMERAL_TYPE))
    declared_type = declspecs->type;
  else if (declspecs->type == error_mark_node)
    error_p = true;

  if (type_uses_auto (declared_type))
    {
      error_at (declspecs->locations[ds_type_spec],
		"%<auto%> can only be specified for variables "
		"or function declarations");
      return error_mark_node;
    }

  if (declared_type && !OVERLOAD_TYPE_P (declared_type))
    declared_type = NULL_TREE;

  if (!declared_type && !saw_friend && !error_p)
    permerror (input_location, "declaration does not declare anything");
  /* Check for an anonymous union.  */
  else if (declared_type && RECORD_OR_UNION_CODE_P (TREE_CODE (declared_type))
	   && TYPE_UNNAMED_P (declared_type))
    {
      /* 7/3 In a simple-declaration, the optional init-declarator-list
	 can be omitted only when declaring a class (clause 9) or
	 enumeration (7.2), that is, when the decl-specifier-seq contains
	 either a class-specifier, an elaborated-type-specifier with
	 a class-key (9.1), or an enum-specifier.  In these cases and
	 whenever a class-specifier or enum-specifier is present in the
	 decl-specifier-seq, the identifiers in these specifiers are among
	 the names being declared by the declaration (as class-name,
	 enum-names, or enumerators, depending on the syntax).  In such
	 cases, and except for the declaration of an unnamed bit-field (9.6),
	 the decl-specifier-seq shall introduce one or more names into the
	 program, or shall redeclare a name introduced by a previous
	 declaration.  [Example:
	     enum { };			// ill-formed
	     typedef class { };		// ill-formed
	 --end example]  */
      if (saw_typedef)
	{
	  error_at (declspecs->locations[ds_typedef],
		    "missing type-name in typedef-declaration");
	  return NULL_TREE;
	}
      /* Anonymous unions are objects, so they can have specifiers.  */;
      SET_ANON_AGGR_TYPE_P (declared_type);

      if (TREE_CODE (declared_type) != UNION_TYPE)
	pedwarn (DECL_SOURCE_LOCATION (TYPE_MAIN_DECL (declared_type)),
		 OPT_Wpedantic, "ISO C++ prohibits anonymous structs");
    }

  else
    {
      if (decl_spec_seq_has_spec_p (declspecs, ds_inline))
	error_at (declspecs->locations[ds_inline],
		  "%<inline%> can only be specified for functions");
      else if (decl_spec_seq_has_spec_p (declspecs, ds_virtual))
	error_at (declspecs->locations[ds_virtual],
		  "%<virtual%> can only be specified for functions");
      else if (saw_friend
	       && (!current_class_type
		   || current_scope () != current_class_type))
	error_at (declspecs->locations[ds_friend],
		  "%<friend%> can only be specified inside a class");
      else if (decl_spec_seq_has_spec_p (declspecs, ds_explicit))
	error_at (declspecs->locations[ds_explicit],
		  "%<explicit%> can only be specified for constructors");
      else if (declspecs->storage_class)
	error_at (declspecs->locations[ds_storage_class],
		  "a storage class can only be specified for objects "
		  "and functions");
      else if (decl_spec_seq_has_spec_p (declspecs, ds_const))
	error_at (declspecs->locations[ds_const],
		  "%<const%> can only be specified for objects and "
		  "functions");
      else if (decl_spec_seq_has_spec_p (declspecs, ds_volatile))
	error_at (declspecs->locations[ds_volatile],
		  "%<volatile%> can only be specified for objects and "
		  "functions");
      else if (decl_spec_seq_has_spec_p (declspecs, ds_restrict))
	error_at (declspecs->locations[ds_restrict],
		  "%<__restrict%> can only be specified for objects and "
		  "functions");
      else if (decl_spec_seq_has_spec_p (declspecs, ds_thread))
	error_at (declspecs->locations[ds_thread],
		  "%<__thread%> can only be specified for objects "
		  "and functions");
      else if (saw_typedef)
	warning_at (declspecs->locations[ds_typedef], 0,
		    "%<typedef%> was ignored in this declaration");
      else if (decl_spec_seq_has_spec_p (declspecs, ds_constexpr))
        error_at (declspecs->locations[ds_constexpr],
		  "%qs cannot be used for type declarations", "constexpr");
      else if (decl_spec_seq_has_spec_p (declspecs, ds_constinit))
	error_at (declspecs->locations[ds_constinit],
		  "%qs cannot be used for type declarations", "constinit");
      else if (decl_spec_seq_has_spec_p (declspecs, ds_consteval))
	error_at (declspecs->locations[ds_consteval],
		  "%qs cannot be used for type declarations", "consteval");
    }

  if (declspecs->attributes && warn_attributes && declared_type)
    {
      location_t loc;
      if (!CLASS_TYPE_P (declared_type)
	  || !CLASSTYPE_TEMPLATE_INSTANTIATION (declared_type))
	/* For a non-template class, use the name location.  */
	loc = location_of (declared_type);
      else
	/* For a template class (an explicit instantiation), use the
	   current location.  */
	loc = input_location;

      if (explicit_type_instantiation_p)
	/* [dcl.attr.grammar]/4:

	       No attribute-specifier-seq shall appertain to an explicit
	       instantiation.  */
	{
	  if (warning_at (loc, OPT_Wattributes,
			  "attribute ignored in explicit instantiation %q#T",
			  declared_type))
	    inform (loc,
		    "no attribute can be applied to "
		    "an explicit instantiation");
	}
      else
	warn_misplaced_attr_for_class_type (loc, declared_type);
    }

  return declared_type;
}

/* Called when a declaration is seen that contains no names to declare.
   If its type is a reference to a structure, union or enum inherited
   from a containing scope, shadow that tag name for the current scope
   with a forward reference.
   If its type defines a new named structure or union
   or defines an enum, it is valid but we need not do anything here.
   Otherwise, it is an error.

   C++: may have to grok the declspecs to learn about static,
   complain for anonymous unions.

   Returns the TYPE declared -- or NULL_TREE if none.  */

tree
shadow_tag (cp_decl_specifier_seq *declspecs)
{
  tree t = check_tag_decl (declspecs,
			   /*explicit_type_instantiation_p=*/false);

  if (!t)
    return NULL_TREE;

  t = maybe_process_partial_specialization (t);
  if (t == error_mark_node)
    return NULL_TREE;

  /* This is where the variables in an anonymous union are
     declared.  An anonymous union declaration looks like:
     union { ... } ;
     because there is no declarator after the union, the parser
     sends that declaration here.  */
  if (ANON_AGGR_TYPE_P (t))
    {
      fixup_anonymous_aggr (t);

      if (TYPE_FIELDS (t))
	{
	  tree decl = grokdeclarator (/*declarator=*/NULL,
				      declspecs, NORMAL, 0, NULL);
	  finish_anon_union (decl);
	}
    }

  return t;
}

/* Decode a "typename", such as "int **", returning a ..._TYPE node.  */

tree
groktypename (cp_decl_specifier_seq *type_specifiers,
	      const cp_declarator *declarator,
	      bool is_template_arg)
{
  tree attrs;
  tree type;
  enum decl_context context
    = is_template_arg ? TEMPLATE_TYPE_ARG : TYPENAME;
  attrs = type_specifiers->attributes;
  type_specifiers->attributes = NULL_TREE;
  type = grokdeclarator (declarator, type_specifiers, context, 0, &attrs);
  if (attrs && type != error_mark_node)
    {
      if (CLASS_TYPE_P (type))
	warning (OPT_Wattributes, "ignoring attributes applied to class type %qT "
		 "outside of definition", type);
      else if (MAYBE_CLASS_TYPE_P (type))
	/* A template type parameter or other dependent type.  */
	warning (OPT_Wattributes, "ignoring attributes applied to dependent "
		 "type %qT without an associated declaration", type);
      else
	cplus_decl_attributes (&type, attrs, 0);
    }
  return type;
}

/* Process a DECLARATOR for a function-scope or namespace-scope
   variable or function declaration.
   (Function definitions go through start_function; class member
   declarations appearing in the body of the class go through
   grokfield.)  The DECL corresponding to the DECLARATOR is returned.
   If an error occurs, the error_mark_node is returned instead.

   DECLSPECS are the decl-specifiers for the declaration.  INITIALIZED is
   SD_INITIALIZED if an explicit initializer is present, or SD_DEFAULTED
   for an explicitly defaulted function, or SD_DELETED for an explicitly
   deleted function, but 0 (SD_UNINITIALIZED) if this is a variable
   implicitly initialized via a default constructor.  It can also be
   SD_DECOMPOSITION which behaves much like SD_INITIALIZED, but we also
   mark the new decl as DECL_DECOMPOSITION_P.

   ATTRIBUTES and PREFIX_ATTRIBUTES are GNU attributes associated with this
   declaration.

   The scope represented by the context of the returned DECL is pushed
   (if it is not the global namespace) and is assigned to
   *PUSHED_SCOPE_P.  The caller is then responsible for calling
   pop_scope on *PUSHED_SCOPE_P if it is set.  */

tree
start_decl (const cp_declarator *declarator,
	    cp_decl_specifier_seq *declspecs,
	    int initialized,
	    tree attributes,
	    tree prefix_attributes,
	    tree *pushed_scope_p)
{
  tree decl;
  tree context;
  bool was_public;
  int flags;
  bool alias;
  tree initial;

  *pushed_scope_p = NULL_TREE;

  if (prefix_attributes != error_mark_node)
    attributes = chainon (attributes, prefix_attributes);

  decl = grokdeclarator (declarator, declspecs, NORMAL, initialized,
			 &attributes);

  if (decl == NULL_TREE || VOID_TYPE_P (decl)
      || decl == error_mark_node
      || prefix_attributes == error_mark_node)
    return error_mark_node;

  context = CP_DECL_CONTEXT (decl);
  if (context != global_namespace)
    *pushed_scope_p = push_scope (context);

  if (initialized && TREE_CODE (decl) == TYPE_DECL)
    {
      error_at (DECL_SOURCE_LOCATION (decl),
		"typedef %qD is initialized (use %qs instead)",
		decl, "decltype");
      return error_mark_node;
    }

  /* Save the DECL_INITIAL value in case it gets clobbered to assist
     with attribute validation.  */
  initial = DECL_INITIAL (decl);

  if (initialized)
    {
      if (! toplevel_bindings_p ()
	  && DECL_EXTERNAL (decl))
	warning (0, "declaration of %q#D has %<extern%> and is initialized",
		 decl);
      DECL_EXTERNAL (decl) = 0;
      if (toplevel_bindings_p ())
	TREE_STATIC (decl) = 1;
      /* Tell 'cplus_decl_attributes' this is an initialized decl,
	 even though we might not yet have the initializer expression.  */
      if (!DECL_INITIAL (decl))
	DECL_INITIAL (decl) = error_mark_node;
    }
  alias = lookup_attribute ("alias", DECL_ATTRIBUTES (decl)) != 0;
  
  if (alias && TREE_CODE (decl) == FUNCTION_DECL)
    record_key_method_defined (decl);

  /* If this is a typedef that names the class for linkage purposes
     (7.1.3p8), apply any attributes directly to the type.  */
  if (TREE_CODE (decl) == TYPE_DECL
      && OVERLOAD_TYPE_P (TREE_TYPE (decl))
      && decl == TYPE_NAME (TYPE_MAIN_VARIANT (TREE_TYPE (decl))))
    flags = ATTR_FLAG_TYPE_IN_PLACE;
  else
    flags = 0;

  /* Set attributes here so if duplicate decl, will have proper attributes.  */
  cplus_decl_attributes (&decl, attributes, flags);

  /* Restore the original DECL_INITIAL that we may have clobbered earlier to
     assist with attribute validation.  */
  DECL_INITIAL (decl) = initial;

  /* Dllimported symbols cannot be defined.  Static data members (which
     can be initialized in-class and dllimported) go through grokfield,
     not here, so we don't need to exclude those decls when checking for
     a definition.  */
  if (initialized && DECL_DLLIMPORT_P (decl))
    {
      error_at (DECL_SOURCE_LOCATION (decl),
		"definition of %q#D is marked %<dllimport%>", decl);
      DECL_DLLIMPORT_P (decl) = 0;
    }

  /* If #pragma weak was used, mark the decl weak now.  */
  if (!processing_template_decl && !DECL_DECOMPOSITION_P (decl))
    maybe_apply_pragma_weak (decl);

  if (TREE_CODE (decl) == FUNCTION_DECL
      && DECL_DECLARED_INLINE_P (decl)
      && DECL_UNINLINABLE (decl)
      && lookup_attribute ("noinline", DECL_ATTRIBUTES (decl)))
    warning_at (DECL_SOURCE_LOCATION (decl), 0,
		"inline function %qD given attribute %qs", decl, "noinline");

  if (TYPE_P (context) && COMPLETE_TYPE_P (complete_type (context)))
    {
      bool this_tmpl = (current_template_depth
			> template_class_depth (context));
      if (VAR_P (decl))
	{
	  tree field = lookup_field (context, DECL_NAME (decl), 0, false);
	  if (field == NULL_TREE
	      || !(VAR_P (field) || variable_template_p (field)))
	    error ("%q+#D is not a static data member of %q#T", decl, context);
	  else if (variable_template_p (field)
		   && (DECL_LANG_SPECIFIC (decl)
		       && DECL_TEMPLATE_SPECIALIZATION (decl)))
	    /* OK, specialization was already checked.  */;
	  else if (variable_template_p (field) && !this_tmpl)
	    {
	      error_at (DECL_SOURCE_LOCATION (decl),
			"non-member-template declaration of %qD", decl);
	      inform (DECL_SOURCE_LOCATION (field), "does not match "
		      "member template declaration here");
	      return error_mark_node;
	    }
	  else
	    {
	      if (variable_template_p (field))
		field = DECL_TEMPLATE_RESULT (field);

	      if (DECL_CONTEXT (field) != context)
		{
		  if (!same_type_p (DECL_CONTEXT (field), context))
		    permerror (input_location, "ISO C++ does not permit %<%T::%D%> "
			       "to be defined as %<%T::%D%>",
			       DECL_CONTEXT (field), DECL_NAME (decl),
			       context, DECL_NAME (decl));
		  DECL_CONTEXT (decl) = DECL_CONTEXT (field);
		}
	      /* Static data member are tricky; an in-class initialization
		 still doesn't provide a definition, so the in-class
		 declaration will have DECL_EXTERNAL set, but will have an
		 initialization.  Thus, duplicate_decls won't warn
		 about this situation, and so we check here.  */
	      if (initialized && DECL_INITIALIZED_IN_CLASS_P (field))
		error ("duplicate initialization of %qD", decl);
	      field = duplicate_decls (decl, field);
	      if (field == error_mark_node)
		return error_mark_node;
	      else if (field)
		decl = field;
	    }
	}
      else
	{
	  tree field = check_classfn (context, decl,
				      this_tmpl
				      ? current_template_parms
				      : NULL_TREE);
	  if (field && field != error_mark_node
	      && duplicate_decls (decl, field))
	    decl = field;
	}

      /* cp_finish_decl sets DECL_EXTERNAL if DECL_IN_AGGR_P is set.  */
      DECL_IN_AGGR_P (decl) = 0;
      /* Do not mark DECL as an explicit specialization if it was not
	 already marked as an instantiation; a declaration should
	 never be marked as a specialization unless we know what
	 template is being specialized.  */
      if (DECL_LANG_SPECIFIC (decl) && DECL_USE_TEMPLATE (decl))
	{
	  SET_DECL_TEMPLATE_SPECIALIZATION (decl);
	  if (TREE_CODE (decl) == FUNCTION_DECL)
	    DECL_COMDAT (decl) = (TREE_PUBLIC (decl)
				  && DECL_DECLARED_INLINE_P (decl));
	  else
	    DECL_COMDAT (decl) = false;

	  /* [temp.expl.spec] An explicit specialization of a static data
	     member of a template is a definition if the declaration
	     includes an initializer; otherwise, it is a declaration.

	     We check for processing_specialization so this only applies
	     to the new specialization syntax.  */
	  if (!initialized && processing_specialization)
	    DECL_EXTERNAL (decl) = 1;
	}

      if (DECL_EXTERNAL (decl) && ! DECL_TEMPLATE_SPECIALIZATION (decl)
	  /* Aliases are definitions. */
	  && !alias)
	permerror (declarator->id_loc,
		   "declaration of %q#D outside of class is not definition",
		   decl);
    }

  /* Create a DECL_LANG_SPECIFIC so that DECL_DECOMPOSITION_P works.  */
  if (initialized == SD_DECOMPOSITION)
    fit_decomposition_lang_decl (decl, NULL_TREE);

  was_public = TREE_PUBLIC (decl);

  if ((DECL_EXTERNAL (decl) || TREE_CODE (decl) == FUNCTION_DECL)
      && current_function_decl)
    {
      /* A function-scope decl of some namespace-scope decl.  */
      DECL_LOCAL_DECL_P (decl) = true;
      if (named_module_purview_p ())
	error_at (declarator->id_loc,
		  "block-scope extern declaration %q#D not permitted"
		  " in module purview", decl);
    }

  /* Enter this declaration into the symbol table.  Don't push the plain
     VAR_DECL for a variable template.  */
  if (!template_parm_scope_p ()
      || !VAR_P (decl))
    decl = maybe_push_decl (decl);

  if (processing_template_decl)
    decl = push_template_decl (decl);

  if (decl == error_mark_node)
    return error_mark_node;

  if (VAR_P (decl)
      && DECL_NAMESPACE_SCOPE_P (decl) && !TREE_PUBLIC (decl) && !was_public
      && !DECL_THIS_STATIC (decl) && !DECL_ARTIFICIAL (decl)
      /* But not templated variables.  */
      && !(DECL_LANG_SPECIFIC (decl) && DECL_TEMPLATE_INFO (decl)))
    {
      /* This is a const variable with implicit 'static'.  Set
	 DECL_THIS_STATIC so we can tell it from variables that are
	 !TREE_PUBLIC because of the anonymous namespace.  */
      gcc_assert (CP_TYPE_CONST_P (TREE_TYPE (decl)) || errorcount);
      DECL_THIS_STATIC (decl) = 1;
    }

  if (current_function_decl && VAR_P (decl)
      && DECL_DECLARED_CONSTEXPR_P (current_function_decl)
      && cxx_dialect < cxx23)
    {
      bool ok = false;
      if (CP_DECL_THREAD_LOCAL_P (decl) && !DECL_REALLY_EXTERN (decl))
	error_at (DECL_SOURCE_LOCATION (decl),
		  "%qD defined %<thread_local%> in %qs function only "
		  "available with %<-std=c++2b%> or %<-std=gnu++2b%>", decl,
		  DECL_IMMEDIATE_FUNCTION_P (current_function_decl)
		  ? "consteval" : "constexpr");
      else if (TREE_STATIC (decl))
	error_at (DECL_SOURCE_LOCATION (decl),
		  "%qD defined %<static%> in %qs function only available "
		  "with %<-std=c++2b%> or %<-std=gnu++2b%>", decl,
		  DECL_IMMEDIATE_FUNCTION_P (current_function_decl)
		  ? "consteval" : "constexpr");
      else
	ok = true;
      if (!ok)
	cp_function_chain->invalid_constexpr = true;
    }

  if (!processing_template_decl && VAR_P (decl))
    start_decl_1 (decl, initialized);

  return decl;
}

/* Process the declaration of a variable DECL.  INITIALIZED is true
   iff DECL is explicitly initialized.  (INITIALIZED is false if the
   variable is initialized via an implicitly-called constructor.)
   This function must be called for ordinary variables (including, for
   example, implicit instantiations of templates), but must not be
   called for template declarations.  */

void
start_decl_1 (tree decl, bool initialized)
{
  gcc_checking_assert (!processing_template_decl);

  if (error_operand_p (decl))
    return;

  gcc_checking_assert (VAR_P (decl));

  tree type = TREE_TYPE (decl);
  bool complete_p = COMPLETE_TYPE_P (type);
  bool aggregate_definition_p
    = MAYBE_CLASS_TYPE_P (type) && !DECL_EXTERNAL (decl);

  /* If an explicit initializer is present, or if this is a definition
     of an aggregate, then we need a complete type at this point.
     (Scalars are always complete types, so there is nothing to
     check.)  This code just sets COMPLETE_P; errors (if necessary)
     are issued below.  */
  if ((initialized || aggregate_definition_p) 
      && !complete_p
      && COMPLETE_TYPE_P (complete_type (type)))
    {
      complete_p = true;
      /* We will not yet have set TREE_READONLY on DECL if the type
	 was "const", but incomplete, before this point.  But, now, we
	 have a complete type, so we can try again.  */
      cp_apply_type_quals_to_decl (cp_type_quals (type), decl);
    }

  if (initialized)
    /* Is it valid for this decl to have an initializer at all?  */
    {
      /* Don't allow initializations for incomplete types except for
	 arrays which might be completed by the initialization.  */
      if (complete_p)
	;			/* A complete type is ok.  */
      else if (type_uses_auto (type))
	; 			/* An auto type is ok.  */
      else if (TREE_CODE (type) != ARRAY_TYPE)
	{
	  error ("variable %q#D has initializer but incomplete type", decl);
	  type = TREE_TYPE (decl) = error_mark_node;
	}
      else if (!COMPLETE_TYPE_P (complete_type (TREE_TYPE (type))))
	{
	  if (DECL_LANG_SPECIFIC (decl) && DECL_TEMPLATE_INFO (decl))
	    error ("elements of array %q#D have incomplete type", decl);
	  /* else we already gave an error in start_decl.  */
	}
    }
  else if (aggregate_definition_p && !complete_p)
    {
      if (type_uses_auto (type))
	gcc_assert (CLASS_PLACEHOLDER_TEMPLATE (type));
      else
	{
	  error ("aggregate %q#D has incomplete type and cannot be defined",
		 decl);
	  /* Change the type so that assemble_variable will give
	     DECL an rtl we can live with: (mem (const_int 0)).  */
	  type = TREE_TYPE (decl) = error_mark_node;
	}
    }

  /* Create a new scope to hold this declaration if necessary.
     Whether or not a new scope is necessary cannot be determined
     until after the type has been completed; if the type is a
     specialization of a class template it is not until after
     instantiation has occurred that TYPE_HAS_NONTRIVIAL_DESTRUCTOR
     will be set correctly.  */
  maybe_push_cleanup_level (type);
}

/* Given a parenthesized list of values INIT, create a CONSTRUCTOR to handle
   C++20 P0960.  TYPE is the type of the object we're initializing.  */

tree
do_aggregate_paren_init (tree init, tree type)
{
  tree val = TREE_VALUE (init);

  if (TREE_CHAIN (init) == NULL_TREE)
    {
      /* If the list has a single element and it's a string literal,
	 then it's the initializer for the array as a whole.  */
      if (TREE_CODE (type) == ARRAY_TYPE
	  && char_type_p (TYPE_MAIN_VARIANT (TREE_TYPE (type)))
	  && TREE_CODE (tree_strip_any_location_wrapper (val))
	     == STRING_CST)
	return val;
      /* Handle non-standard extensions like compound literals.  This also
	 prevents triggering aggregate parenthesized-initialization in
	 compiler-generated code for =default.  */
      else if (same_type_ignoring_top_level_qualifiers_p (type,
							  TREE_TYPE (val)))
	return val;
    }

  init = build_constructor_from_list (init_list_type_node, init);
  CONSTRUCTOR_IS_DIRECT_INIT (init) = true;
  CONSTRUCTOR_IS_PAREN_INIT (init) = true;
  return init;
}

/* Handle initialization of references.  DECL, TYPE, and INIT have the
   same meaning as in cp_finish_decl.  *CLEANUP must be NULL on entry,
   but will be set to a new CLEANUP_STMT if a temporary is created
   that must be destroyed subsequently.

   Returns an initializer expression to use to initialize DECL, or
   NULL if the initialization can be performed statically.

   Quotes on semantics can be found in ARM 8.4.3.  */

static tree
grok_reference_init (tree decl, tree type, tree init, int flags)
{
  if (init == NULL_TREE)
    {
      if ((DECL_LANG_SPECIFIC (decl) == 0
	   || DECL_IN_AGGR_P (decl) == 0)
	  && ! DECL_THIS_EXTERN (decl))
	error_at (DECL_SOURCE_LOCATION (decl),
		  "%qD declared as reference but not initialized", decl);
      return NULL_TREE;
    }

  tree ttype = TREE_TYPE (type);
  if (TREE_CODE (init) == TREE_LIST)
    {
      /* This handles (C++20 only) code like

	   const A& r(1, 2, 3);

	 where we treat the parenthesized list as a CONSTRUCTOR.  */
      if (TREE_TYPE (init) == NULL_TREE
	  && CP_AGGREGATE_TYPE_P (ttype)
	  && !DECL_DECOMPOSITION_P (decl)
	  && (cxx_dialect >= cxx20))
	{
	  /* We don't know yet if we should treat const A& r(1) as
	     const A& r{1}.  */
	  if (list_length (init) == 1)
	    {
	      flags |= LOOKUP_AGGREGATE_PAREN_INIT;
	      init = build_x_compound_expr_from_list (init, ELK_INIT,
						      tf_warning_or_error);
	    }
	  /* If the list had more than one element, the code is ill-formed
	     pre-C++20, so we can build a constructor right away.  */
	  else
	    init = do_aggregate_paren_init (init, ttype);
	}
      else
	init = build_x_compound_expr_from_list (init, ELK_INIT,
						tf_warning_or_error);
    }

  if (TREE_CODE (ttype) != ARRAY_TYPE
      && TREE_CODE (TREE_TYPE (init)) == ARRAY_TYPE)
    /* Note: default conversion is only called in very special cases.  */
    init = decay_conversion (init, tf_warning_or_error);

  /* check_initializer handles this for non-reference variables, but for
     references we need to do it here or the initializer will get the
     incomplete array type and confuse later calls to
     cp_complete_array_type.  */
  if (TREE_CODE (ttype) == ARRAY_TYPE
      && TYPE_DOMAIN (ttype) == NULL_TREE
      && (BRACE_ENCLOSED_INITIALIZER_P (init)
	  || TREE_CODE (init) == STRING_CST))
    {
      cp_complete_array_type (&ttype, init, false);
      if (ttype != TREE_TYPE (type))
	type = cp_build_reference_type (ttype, TYPE_REF_IS_RVALUE (type));
    }

  /* Convert INIT to the reference type TYPE.  This may involve the
     creation of a temporary, whose lifetime must be the same as that
     of the reference.  If so, a DECL_EXPR for the temporary will be
     added just after the DECL_EXPR for DECL.  That's why we don't set
     DECL_INITIAL for local references (instead assigning to them
     explicitly); we need to allow the temporary to be initialized
     first.  */
  return initialize_reference (type, init, flags,
			       tf_warning_or_error);
}

/* Designated initializers in arrays are not supported in GNU C++.
   The parser cannot detect this error since it does not know whether
   a given brace-enclosed initializer is for a class type or for an
   array.  This function checks that CE does not use a designated
   initializer.  If it does, an error is issued.  Returns true if CE
   is valid, i.e., does not have a designated initializer.  */

bool
check_array_designated_initializer (constructor_elt *ce,
				    unsigned HOST_WIDE_INT index)
{
  /* Designated initializers for array elements are not supported.  */
  if (ce->index)
    {
      /* The parser only allows identifiers as designated
	 initializers.  */
      if (ce->index == error_mark_node)
	{
	  error ("name used in a GNU-style designated "
		 "initializer for an array");
	  return false;
	}
      else if (identifier_p (ce->index))
	{
	  error ("name %qD used in a GNU-style designated "
		 "initializer for an array", ce->index);
	  return false;
	}

      tree ce_index = build_expr_type_conversion (WANT_INT | WANT_ENUM,
						  ce->index, true);
      if (ce_index
	  && INTEGRAL_OR_UNSCOPED_ENUMERATION_TYPE_P (TREE_TYPE (ce_index))
	  && (TREE_CODE (ce_index = fold_non_dependent_expr (ce_index))
	      == INTEGER_CST))
	{
	  /* A C99 designator is OK if it matches the current index.  */
	  if (wi::to_wide (ce_index) == index)
	    {
	      ce->index = ce_index;
	      return true;
	    }
	  else
	    sorry ("non-trivial designated initializers not supported");
	}
      else
	error_at (cp_expr_loc_or_input_loc (ce->index),
		  "C99 designator %qE is not an integral constant-expression",
		  ce->index);

      return false;
    }

  return true;
}

/* When parsing `int a[] = {1, 2};' we don't know the size of the
   array until we finish parsing the initializer.  If that's the
   situation we're in, update DECL accordingly.  */

static void
maybe_deduce_size_from_array_init (tree decl, tree init)
{
  tree type = TREE_TYPE (decl);

  if (TREE_CODE (type) == ARRAY_TYPE
      && TYPE_DOMAIN (type) == NULL_TREE
      && TREE_CODE (decl) != TYPE_DECL)
    {
      /* do_default is really a C-ism to deal with tentative definitions.
	 But let's leave it here to ease the eventual merge.  */
      int do_default = !DECL_EXTERNAL (decl);
      tree initializer = init ? init : DECL_INITIAL (decl);
      int failure = 0;

      /* Check that there are no designated initializers in INIT, as
	 those are not supported in GNU C++, and as the middle-end
	 will crash if presented with a non-numeric designated
	 initializer.  */
      if (initializer && BRACE_ENCLOSED_INITIALIZER_P (initializer))
	{
	  vec<constructor_elt, va_gc> *v = CONSTRUCTOR_ELTS (initializer);
	  constructor_elt *ce;
	  HOST_WIDE_INT i;
	  FOR_EACH_VEC_SAFE_ELT (v, i, ce)
	    {
	      if (instantiation_dependent_expression_p (ce->index))
		return;
	      if (!check_array_designated_initializer (ce, i))
		failure = 1;
	      /* If an un-designated initializer is type-dependent, we can't
		 check brace elision yet.  */
	      if (ce->index == NULL_TREE
		  && type_dependent_expression_p (ce->value))
		return;
	    }
	}

      if (failure)
	TREE_TYPE (decl) = error_mark_node;
      else
	{
	  failure = cp_complete_array_type (&TREE_TYPE (decl), initializer,
					    do_default);
	  if (failure == 1)
	    {
	      error_at (cp_expr_loc_or_loc (initializer,
					 DECL_SOURCE_LOCATION (decl)),
			"initializer fails to determine size of %qD", decl);
	    }
	  else if (failure == 2)
	    {
	      if (do_default)
		{
		  error_at (DECL_SOURCE_LOCATION (decl),
			    "array size missing in %qD", decl);
		}
	      /* If a `static' var's size isn't known, make it extern as
		 well as static, so it does not get allocated.  If it's not
		 `static', then don't mark it extern; finish_incomplete_decl
		 will give it a default size and it will get allocated.  */
	      else if (!pedantic && TREE_STATIC (decl) && !TREE_PUBLIC (decl))
		DECL_EXTERNAL (decl) = 1;
	    }
	  else if (failure == 3)
	    {
	      error_at (DECL_SOURCE_LOCATION (decl),
			"zero-size array %qD", decl);
	    }
	}

      cp_apply_type_quals_to_decl (cp_type_quals (TREE_TYPE (decl)), decl);

      relayout_decl (decl);
    }
}

/* Set DECL_SIZE, DECL_ALIGN, etc. for DECL (a VAR_DECL), and issue
   any appropriate error messages regarding the layout.  */

static void
layout_var_decl (tree decl)
{
  tree type;

  type = TREE_TYPE (decl);
  if (type == error_mark_node)
    return;

  /* If we haven't already laid out this declaration, do so now.
     Note that we must not call complete type for an external object
     because it's type might involve templates that we are not
     supposed to instantiate yet.  (And it's perfectly valid to say
     `extern X x' for some incomplete type `X'.)  */
  if (!DECL_EXTERNAL (decl))
    complete_type (type);
  if (!DECL_SIZE (decl)
      && TREE_TYPE (decl) != error_mark_node
      && complete_or_array_type_p (type))
    layout_decl (decl, 0);

  if (!DECL_EXTERNAL (decl) && DECL_SIZE (decl) == NULL_TREE)
    {
      /* An automatic variable with an incomplete type: that is an error.
	 Don't talk about array types here, since we took care of that
	 message in grokdeclarator.  */
      error_at (DECL_SOURCE_LOCATION (decl),
		"storage size of %qD isn%'t known", decl);
      TREE_TYPE (decl) = error_mark_node;
    }
#if 0
  /* Keep this code around in case we later want to control debug info
     based on whether a type is "used".  (jason 1999-11-11) */

  else if (!DECL_EXTERNAL (decl) && MAYBE_CLASS_TYPE_P (ttype))
    /* Let debugger know it should output info for this type.  */
    note_debug_info_needed (ttype);

  if (TREE_STATIC (decl) && DECL_CLASS_SCOPE_P (decl))
    note_debug_info_needed (DECL_CONTEXT (decl));
#endif

  if ((DECL_EXTERNAL (decl) || TREE_STATIC (decl))
      && DECL_SIZE (decl) != NULL_TREE
      && ! TREE_CONSTANT (DECL_SIZE (decl)))
    {
      if (TREE_CODE (DECL_SIZE (decl)) == INTEGER_CST
	  && !DECL_LOCAL_DECL_P (decl))
	constant_expression_warning (DECL_SIZE (decl));
      else
	{
	  error_at (DECL_SOURCE_LOCATION (decl),
		    "storage size of %qD isn%'t constant", decl);
	  TREE_TYPE (decl) = error_mark_node;
	  type = error_mark_node;
	}
    }

  /* If the final element initializes a flexible array field, add the size of
     that initializer to DECL's size.  */
  if (type != error_mark_node
      && DECL_INITIAL (decl)
      && TREE_CODE (DECL_INITIAL (decl)) == CONSTRUCTOR
      && !vec_safe_is_empty (CONSTRUCTOR_ELTS (DECL_INITIAL (decl)))
      && DECL_SIZE (decl) != NULL_TREE
      && TREE_CODE (DECL_SIZE (decl)) == INTEGER_CST
      && TYPE_SIZE (type) != NULL_TREE
      && TREE_CODE (TYPE_SIZE (type)) == INTEGER_CST
      && tree_int_cst_equal (DECL_SIZE (decl), TYPE_SIZE (type)))
    {
      constructor_elt &elt = CONSTRUCTOR_ELTS (DECL_INITIAL (decl))->last ();
      if (elt.index)
	{
	  tree itype = TREE_TYPE (elt.index);
	  tree vtype = TREE_TYPE (elt.value);
	  if (TREE_CODE (itype) == ARRAY_TYPE
	      && TYPE_DOMAIN (itype) == NULL
	      && TREE_CODE (vtype) == ARRAY_TYPE
	      && COMPLETE_TYPE_P (vtype))
	    {
	      DECL_SIZE (decl)
		= size_binop (PLUS_EXPR, DECL_SIZE (decl), TYPE_SIZE (vtype));
	      DECL_SIZE_UNIT (decl)
		= size_binop (PLUS_EXPR, DECL_SIZE_UNIT (decl),
			      TYPE_SIZE_UNIT (vtype));
	    }
	}
    }
}

/* If a local static variable is declared in an inline function, or if
   we have a weak definition, we must endeavor to create only one
   instance of the variable at link-time.  */

void
maybe_commonize_var (tree decl)
{
  /* Don't mess with __FUNCTION__ and similar.  */
  if (DECL_ARTIFICIAL (decl))
    return;

  /* Static data in a function with comdat linkage also has comdat
     linkage.  */
  if ((TREE_STATIC (decl)
       && DECL_FUNCTION_SCOPE_P (decl)
       && vague_linkage_p (DECL_CONTEXT (decl)))
      || (TREE_PUBLIC (decl) && DECL_INLINE_VAR_P (decl)))
    {
      if (flag_weak)
	{
	  /* With weak symbols, we simply make the variable COMDAT;
	     that will cause copies in multiple translations units to
	     be merged.  */
	  comdat_linkage (decl);
	}
      else
	{
	  if (DECL_INITIAL (decl) == NULL_TREE
	      || DECL_INITIAL (decl) == error_mark_node)
	    {
	      /* Without weak symbols, we can use COMMON to merge
		 uninitialized variables.  */
	      TREE_PUBLIC (decl) = 1;
	      DECL_COMMON (decl) = 1;
	    }
	  else
	    {
	      /* While for initialized variables, we must use internal
		 linkage -- which means that multiple copies will not
		 be merged.  */
	      TREE_PUBLIC (decl) = 0;
	      DECL_COMMON (decl) = 0;
	      DECL_INTERFACE_KNOWN (decl) = 1;
	      const char *msg;
	      if (DECL_INLINE_VAR_P (decl))
		msg = G_("sorry: semantics of inline variable "
			 "%q#D are wrong (you%'ll wind up with "
			 "multiple copies)");
	      else
		msg = G_("sorry: semantics of inline function "
			 "static data %q#D are wrong (you%'ll wind "
			 "up with multiple copies)");
	      if (warning_at (DECL_SOURCE_LOCATION (decl), 0,
			      msg, decl))
		inform (DECL_SOURCE_LOCATION (decl),
			"you can work around this by removing the initializer");
	    }
	}
    }
}

/* Issue an error message if DECL is an uninitialized const variable.
   CONSTEXPR_CONTEXT_P is true when the function is called in a constexpr
   context from potential_constant_expression.  Returns true if all is well,
   false otherwise.  */

bool
check_for_uninitialized_const_var (tree decl, bool constexpr_context_p,
				   tsubst_flags_t complain)
{
  tree type = strip_array_types (TREE_TYPE (decl));

  /* ``Unless explicitly declared extern, a const object does not have
     external linkage and must be initialized. ($8.4; $12.1)'' ARM
     7.1.6 */
  if (VAR_P (decl)
      && !TYPE_REF_P (type)
      && (CP_TYPE_CONST_P (type)
	  /* C++20 permits trivial default initialization in constexpr
	     context (P1331R2).  */
	  || (cxx_dialect < cxx20
	      && (constexpr_context_p
		  || var_in_constexpr_fn (decl))))
      && !DECL_NONTRIVIALLY_INITIALIZED_P (decl))
    {
      tree field = default_init_uninitialized_part (type);
      if (!field)
	return true;

      bool show_notes = true;

      if (!constexpr_context_p || cxx_dialect >= cxx20)
	{
	  if (CP_TYPE_CONST_P (type))
	    {
	      if (complain & tf_error)
		show_notes = permerror (DECL_SOURCE_LOCATION (decl),
				        "uninitialized %<const %D%>", decl);
	    }
	  else
	    {
	      if (!is_instantiation_of_constexpr (current_function_decl)
		  && (complain & tf_error))
		error_at (DECL_SOURCE_LOCATION (decl),
			  "uninitialized variable %qD in %<constexpr%> "
			  "function", decl);
	      else
		show_notes = false;
	      cp_function_chain->invalid_constexpr = true;
	    }
	}
      else if (complain & tf_error)
	error_at (DECL_SOURCE_LOCATION (decl),
		  "uninitialized variable %qD in %<constexpr%> context",
		  decl);

      if (show_notes && CLASS_TYPE_P (type) && (complain & tf_error))
	{
	  tree defaulted_ctor;

	  inform (DECL_SOURCE_LOCATION (TYPE_MAIN_DECL (type)),
		  "%q#T has no user-provided default constructor", type);
	  defaulted_ctor = in_class_defaulted_default_constructor (type);
	  if (defaulted_ctor)
	    inform (DECL_SOURCE_LOCATION (defaulted_ctor),
		    "constructor is not user-provided because it is "
		    "explicitly defaulted in the class body");
	  inform (DECL_SOURCE_LOCATION (field),
		  "and the implicitly-defined constructor does not "
		  "initialize %q#D", field);
	}

      return false;
    }

  return true;
}

/* Structure holding the current initializer being processed by reshape_init.
   CUR is a pointer to the current element being processed, END is a pointer
   after the last element present in the initializer.  */
struct reshape_iter
{
  constructor_elt *cur;
  constructor_elt *end;
};

static tree reshape_init_r (tree, reshape_iter *, tree, tsubst_flags_t);

/* FIELD is an element of TYPE_FIELDS or NULL.  In the former case, the value
   returned is the next FIELD_DECL (possibly FIELD itself) that can be
   initialized.  If there are no more such fields, the return value
   will be NULL.  */

tree
next_initializable_field (tree field)
{
  while (field
	 && (TREE_CODE (field) != FIELD_DECL
	     || DECL_UNNAMED_BIT_FIELD (field)
	     || (DECL_ARTIFICIAL (field)
		 /* In C++17, don't skip base class fields.  */
		 && !(cxx_dialect >= cxx17 && DECL_FIELD_IS_BASE (field))
		 /* Don't skip vptr fields.  We might see them when we're
		    called from reduced_constant_expression_p.  */
		 && !DECL_VIRTUAL_P (field))))
    field = DECL_CHAIN (field);

  return field;
}

/* FIELD is an element of TYPE_FIELDS or NULL.  In the former case, the value
   returned is the next FIELD_DECL (possibly FIELD itself) that corresponds
   to a subobject.  If there are no more such fields, the return value will be
   NULL.  */

tree
next_subobject_field (tree field)
{
  while (field
	 && (TREE_CODE (field) != FIELD_DECL
	     || DECL_UNNAMED_BIT_FIELD (field)
	     || (DECL_ARTIFICIAL (field)
		 && !DECL_FIELD_IS_BASE (field)
		 && !DECL_VIRTUAL_P (field))))
     field = DECL_CHAIN (field);

  return field;
}

/* Return true for [dcl.init.list] direct-list-initialization from
   single element of enumeration with a fixed underlying type.  */

bool
is_direct_enum_init (tree type, tree init)
{
  if (cxx_dialect >= cxx17
      && TREE_CODE (type) == ENUMERAL_TYPE
      && ENUM_FIXED_UNDERLYING_TYPE_P (type)
      && TREE_CODE (init) == CONSTRUCTOR
      && CONSTRUCTOR_IS_DIRECT_INIT (init)
      && CONSTRUCTOR_NELTS (init) == 1
      /* DR 2374: The single element needs to be implicitly
	 convertible to the underlying type of the enum.  */
      && can_convert_arg (ENUM_UNDERLYING_TYPE (type),
			  TREE_TYPE (CONSTRUCTOR_ELT (init, 0)->value),
			  CONSTRUCTOR_ELT (init, 0)->value,
			  LOOKUP_IMPLICIT, tf_none))
    return true;
  return false;
}

/* Subroutine of reshape_init_array and reshape_init_vector, which does
   the actual work. ELT_TYPE is the element type of the array. MAX_INDEX is an
   INTEGER_CST representing the size of the array minus one (the maximum index),
   or NULL_TREE if the array was declared without specifying the size. D is
   the iterator within the constructor.  */

static tree
reshape_init_array_1 (tree elt_type, tree max_index, reshape_iter *d,
		      tree first_initializer_p, tsubst_flags_t complain)
{
  tree new_init;
  bool sized_array_p = (max_index && TREE_CONSTANT (max_index));
  unsigned HOST_WIDE_INT max_index_cst = 0;
  unsigned HOST_WIDE_INT index;

  /* The initializer for an array is always a CONSTRUCTOR.  If this is the
     outermost CONSTRUCTOR and the element type is non-aggregate, we don't need
     to build a new one.  But don't reuse if not complaining; if this is
     tentative, we might also reshape to another type (95319).  */
  bool reuse = (first_initializer_p
		&& (complain & tf_error)
		&& !CP_AGGREGATE_TYPE_P (elt_type)
		&& !TREE_SIDE_EFFECTS (first_initializer_p));
  if (reuse)
    new_init = first_initializer_p;
  else
    new_init = build_constructor (init_list_type_node, NULL);

  if (sized_array_p)
    {
      /* Minus 1 is used for zero sized arrays.  */
      if (integer_all_onesp (max_index))
	return new_init;

      if (tree_fits_uhwi_p (max_index))
	max_index_cst = tree_to_uhwi (max_index);
      /* sizetype is sign extended, not zero extended.  */
      else
	max_index_cst = tree_to_uhwi (fold_convert (size_type_node, max_index));
    }

  /* Loop until there are no more initializers.  */
  for (index = 0;
       d->cur != d->end && (!sized_array_p || index <= max_index_cst);
       ++index)
    {
      tree elt_init;
      constructor_elt *old_cur = d->cur;

      if (d->cur->index)
	CONSTRUCTOR_IS_DESIGNATED_INIT (new_init) = true;
      check_array_designated_initializer (d->cur, index);
      elt_init = reshape_init_r (elt_type, d,
				 /*first_initializer_p=*/NULL_TREE,
				 complain);
      if (elt_init == error_mark_node)
	return error_mark_node;
      tree idx = size_int (index);
      if (reuse)
	{
	  old_cur->index = idx;
	  old_cur->value = elt_init;
	}
      else
	CONSTRUCTOR_APPEND_ELT (CONSTRUCTOR_ELTS (new_init),
				idx, elt_init);
      if (!TREE_CONSTANT (elt_init))
	TREE_CONSTANT (new_init) = false;

      /* This can happen with an invalid initializer (c++/54501).  */
      if (d->cur == old_cur && !sized_array_p)
	break;
    }

  return new_init;
}

/* Subroutine of reshape_init_r, processes the initializers for arrays.
   Parameters are the same of reshape_init_r.  */

static tree
reshape_init_array (tree type, reshape_iter *d, tree first_initializer_p,
		    tsubst_flags_t complain)
{
  tree max_index = NULL_TREE;

  gcc_assert (TREE_CODE (type) == ARRAY_TYPE);

  if (TYPE_DOMAIN (type))
    max_index = array_type_nelts (type);

  return reshape_init_array_1 (TREE_TYPE (type), max_index, d,
			       first_initializer_p, complain);
}

/* Subroutine of reshape_init_r, processes the initializers for vectors.
   Parameters are the same of reshape_init_r.  */

static tree
reshape_init_vector (tree type, reshape_iter *d, tsubst_flags_t complain)
{
  tree max_index = NULL_TREE;

  gcc_assert (VECTOR_TYPE_P (type));

  if (COMPOUND_LITERAL_P (d->cur->value))
    {
      tree value = d->cur->value;
      if (!same_type_p (TREE_TYPE (value), type))
	{
	  if (complain & tf_error)
	    error ("invalid type %qT as initializer for a vector of type %qT",
		   TREE_TYPE (d->cur->value), type);
	  value = error_mark_node;
	}
      ++d->cur;
      return value;
    }

  /* For a vector, we initialize it as an array of the appropriate size.  */
  if (VECTOR_TYPE_P (type))
    max_index = size_int (TYPE_VECTOR_SUBPARTS (type) - 1);

  return reshape_init_array_1 (TREE_TYPE (type), max_index, d,
			       NULL_TREE, complain);
}

/* Subroutine of reshape_init*: We're initializing an element with TYPE from
   INIT, in isolation from any designator or other initializers.  */

static tree
reshape_single_init (tree type, tree init, tsubst_flags_t complain)
{
  /* We could also implement this by wrapping init in a new CONSTRUCTOR and
     calling reshape_init, but this way can just live on the stack.  */
  constructor_elt elt = { /*index=*/NULL_TREE, init };
  reshape_iter iter = { &elt, &elt + 1 };
  return reshape_init_r (type, &iter,
			 /*first_initializer_p=*/NULL_TREE,
			 complain);
}

/* Subroutine of reshape_init_r, processes the initializers for classes
   or union. Parameters are the same of reshape_init_r.  */

static tree
reshape_init_class (tree type, reshape_iter *d, bool first_initializer_p,
		    tsubst_flags_t complain)
{
  tree field;
  tree new_init;

  gcc_assert (CLASS_TYPE_P (type));

  /* The initializer for a class is always a CONSTRUCTOR.  */
  new_init = build_constructor (init_list_type_node, NULL);

  int binfo_idx = -1;
  tree binfo = TYPE_BINFO (type);
  tree base_binfo = NULL_TREE;
  if (cxx_dialect >= cxx17 && uses_template_parms (type))
    {
      /* We get here from maybe_aggr_guide for C++20 class template argument
	 deduction.  In this case we need to look through the binfo because a
	 template doesn't have base fields.  */
      binfo_idx = 0;
      BINFO_BASE_ITERATE (binfo, binfo_idx, base_binfo);
    }
  if (base_binfo)
    field = base_binfo;
  else
    field = next_initializable_field (TYPE_FIELDS (type));

  if (!field)
    {
      /* [dcl.init.aggr]

	An initializer for an aggregate member that is an
	empty class shall have the form of an empty
	initializer-list {}.  */
      if (!first_initializer_p)
	{
	  if (complain & tf_error)
	    error ("initializer for %qT must be brace-enclosed", type);
	  return error_mark_node;
	}
      return new_init;
    }

  /* For C++20 CTAD, handle pack expansions in the base list.  */
  tree last_was_pack_expansion = NULL_TREE;

  /* Loop through the initializable fields, gathering initializers.  */
  while (d->cur != d->end)
    {
      tree field_init;
      constructor_elt *old_cur = d->cur;
      bool direct_desig = false;

      /* Handle C++20 designated initializers.  */
      if (d->cur->index)
	{
	  if (d->cur->index == error_mark_node)
	    return error_mark_node;

	  if (TREE_CODE (d->cur->index) == FIELD_DECL)
	    {
	      /* We already reshaped this.  */
	      if (field != d->cur->index)
		{
		  if (tree id = DECL_NAME (d->cur->index))
		    gcc_checking_assert (d->cur->index
					 == get_class_binding (type, id));
		  field = d->cur->index;
		}
	    }
	  else if (TREE_CODE (d->cur->index) == IDENTIFIER_NODE)
	    {
	      CONSTRUCTOR_IS_DESIGNATED_INIT (new_init) = true;
	      field = get_class_binding (type, d->cur->index);
	      direct_desig = true;
	    }
	  else
	    {
	      if (complain & tf_error)
		error ("%<[%E] =%> used in a GNU-style designated initializer"
		       " for class %qT", d->cur->index, type);
	      return error_mark_node;
	    }

	  if (!field && ANON_AGGR_TYPE_P (type))
	    /* Apparently the designator isn't for a member of this anonymous
	       struct, so head back to the enclosing class.  */
	    break;

	  if (!field || TREE_CODE (field) != FIELD_DECL)
	    {
	      if (complain & tf_error)
		error ("%qT has no non-static data member named %qD", type,
		       d->cur->index);
	      return error_mark_node;
	    }

	  /* If the element is an anonymous union object and the initializer
	     list is a designated-initializer-list, the anonymous union object
	     is initialized by the designated-initializer-list { D }, where D
	     is the designated-initializer-clause naming a member of the
	     anonymous union object.  */
	  tree ictx = DECL_CONTEXT (field);
	  if (!same_type_ignoring_top_level_qualifiers_p (ictx, type))
	    {
	      /* Find the anon aggr that is a direct member of TYPE.  */
	      while (ANON_AGGR_TYPE_P (ictx))
		{
		  tree cctx = TYPE_CONTEXT (ictx);
		  if (same_type_ignoring_top_level_qualifiers_p (cctx, type))
		    goto found;
		  ictx = cctx;
		}

	      /* Not found, e.g. FIELD is a member of a base class.  */
	      if (complain & tf_error)
		error ("%qD is not a direct member of %qT", field, type);
	      return error_mark_node;

	    found:
	      /* Now find the TYPE member with that anon aggr type.  */
	      tree aafield = TYPE_FIELDS (type);
	      for (; aafield; aafield = TREE_CHAIN (aafield))
		if (TREE_TYPE (aafield) == ictx)
		  break;
	      gcc_assert (aafield);
	      field = aafield;
	      direct_desig = false;
	    }
	}

      /* If we processed all the member of the class, we are done.  */
      if (!field)
	break;

      last_was_pack_expansion = (PACK_EXPANSION_P (TREE_TYPE (field))
				 ? field : NULL_TREE);
      if (last_was_pack_expansion)
	/* Each non-trailing aggregate element that is a pack expansion is
	   assumed to correspond to no elements of the initializer list.  */
	goto continue_;

      if (direct_desig)
	{
	  /* The designated field F is initialized from this one element.

	     Note that we don't want to do this if we found the designator
	     inside an anon aggr above; we use the normal code to implement:

	     "If the element is an anonymous union member and the initializer
	     list is a brace-enclosed designated- initializer-list, the element
	     is initialized by the designated-initializer-list { D }, where D
	     is the designated- initializer-clause naming a member of the
	     anonymous union member."  */
	  field_init = reshape_single_init (TREE_TYPE (field),
					    d->cur->value, complain);
	  d->cur++;
	}
      else
	field_init = reshape_init_r (TREE_TYPE (field), d,
				     /*first_initializer_p=*/NULL_TREE,
				     complain);

      if (field_init == error_mark_node)
	return error_mark_node;

      if (d->cur == old_cur && d->cur->index)
	{
	  /* This can happen with an invalid initializer for a flexible
	     array member (c++/54441).  */
	  if (complain & tf_error)
	    error ("invalid initializer for %q#D", field);
	  return error_mark_node;
	}

      CONSTRUCTOR_APPEND_ELT (CONSTRUCTOR_ELTS (new_init), field, field_init);

      /* [dcl.init.aggr]

	When a union  is  initialized with a brace-enclosed
	initializer, the braces shall only contain an
	initializer for the first member of the union.  */
      if (TREE_CODE (type) == UNION_TYPE)
	break;

    continue_:
      if (base_binfo)
	{
	  if (BINFO_BASE_ITERATE (binfo, ++binfo_idx, base_binfo))
	    field = base_binfo;
	  else
	    field = next_initializable_field (TYPE_FIELDS (type));
	}
      else
	field = next_initializable_field (DECL_CHAIN (field));
    }

  /* A trailing aggregate element that is a pack expansion is assumed to
     correspond to all remaining elements of the initializer list (if any).  */
  if (last_was_pack_expansion)
    {
      CONSTRUCTOR_APPEND_ELT (CONSTRUCTOR_ELTS (new_init),
			      last_was_pack_expansion, d->cur->value);
      while (d->cur != d->end)
	d->cur++;
    }

  return new_init;
}

/* Subroutine of reshape_init_r.  We're in a context where C99 initializer
   designators are not valid; either complain or return true to indicate
   that reshape_init_r should return error_mark_node.  */

static bool
has_designator_problem (reshape_iter *d, tsubst_flags_t complain)
{
  if (d->cur->index)
    {
      if (complain & tf_error)
	error_at (cp_expr_loc_or_input_loc (d->cur->index),
		  "C99 designator %qE outside aggregate initializer",
		  d->cur->index);
      else
	return true;
    }
  return false;
}

/* Subroutine of reshape_init, which processes a single initializer (part of
   a CONSTRUCTOR). TYPE is the type of the variable being initialized, D is the
   iterator within the CONSTRUCTOR which points to the initializer to process.
   If this is the first initializer of the outermost CONSTRUCTOR node,
   FIRST_INITIALIZER_P is that CONSTRUCTOR; otherwise, it is NULL_TREE.  */

static tree
reshape_init_r (tree type, reshape_iter *d, tree first_initializer_p,
		tsubst_flags_t complain)
{
  tree init = d->cur->value;

  if (error_operand_p (init))
    return error_mark_node;

  if (first_initializer_p && !CP_AGGREGATE_TYPE_P (type)
      && has_designator_problem (d, complain))
    return error_mark_node;

  tree stripped_init = tree_strip_any_location_wrapper (init);

  if (TREE_CODE (type) == COMPLEX_TYPE)
    {
      /* A complex type can be initialized from one or two initializers,
	 but braces are not elided.  */
      d->cur++;
      if (BRACE_ENCLOSED_INITIALIZER_P (stripped_init))
	{
	  if (CONSTRUCTOR_NELTS (stripped_init) > 2)
	    {
	      if (complain & tf_error)
		error ("too many initializers for %qT", type);
	      else
		return error_mark_node;
	    }
	}
      else if (first_initializer_p && d->cur != d->end)
	{
	  vec<constructor_elt, va_gc> *v = 0;
	  CONSTRUCTOR_APPEND_ELT (v, NULL_TREE, init);
	  CONSTRUCTOR_APPEND_ELT (v, NULL_TREE, d->cur->value);
	  if (has_designator_problem (d, complain))
	    return error_mark_node;
	  d->cur++;
	  init = build_constructor (init_list_type_node, v);
	}
      return init;
    }

  /* A non-aggregate type is always initialized with a single
     initializer.  */
  if (!CP_AGGREGATE_TYPE_P (type)
      /* As is an array with dependent bound, which we can see
	 during C++20 aggregate CTAD.  */
      || (cxx_dialect >= cxx20
	  && TREE_CODE (type) == ARRAY_TYPE
	  && uses_template_parms (TYPE_DOMAIN (type))))
    {
      /* It is invalid to initialize a non-aggregate type with a
	 brace-enclosed initializer before C++0x.
	 We need to check for BRACE_ENCLOSED_INITIALIZER_P here because
	 of g++.old-deja/g++.mike/p7626.C: a pointer-to-member constant is
	 a CONSTRUCTOR (with a record type).  */
      if (TREE_CODE (stripped_init) == CONSTRUCTOR
	  /* Don't complain about a capture-init.  */
	  && !CONSTRUCTOR_IS_DIRECT_INIT (stripped_init)
	  && BRACE_ENCLOSED_INITIALIZER_P (stripped_init))  /* p7626.C */
	{
	  if (SCALAR_TYPE_P (type))
	    {
	      if (cxx_dialect < cxx11)
		{
		  if (complain & tf_error)
		    error ("braces around scalar initializer for type %qT",
			   type);
		  init = error_mark_node;
		}
	      else if (first_initializer_p
		       || (CONSTRUCTOR_NELTS (stripped_init) > 0
			   && (BRACE_ENCLOSED_INITIALIZER_P
			       (CONSTRUCTOR_ELT (stripped_init,0)->value))))
		{
		  if (complain & tf_error)
		    error ("too many braces around scalar initializer "
		           "for type %qT", type);
		  init = error_mark_node;
		}
	    }
	  else
	    maybe_warn_cpp0x (CPP0X_INITIALIZER_LISTS);
	}

      d->cur++;
      return init;
    }

  /* "If T is a class type and the initializer list has a single element of
     type cv U, where U is T or a class derived from T, the object is
     initialized from that element."  Even if T is an aggregate.  */
  if (cxx_dialect >= cxx11 && (CLASS_TYPE_P (type) || VECTOR_TYPE_P (type))
      && first_initializer_p
      /* But not if it's a designated init.  */
      && !d->cur->index
      && d->end - d->cur == 1
      && reference_related_p (type, TREE_TYPE (init)))
    {
      d->cur++;
      return init;
    }

  /* [dcl.init.aggr]

     All implicit type conversions (clause _conv_) are considered when
     initializing the aggregate member with an initializer from an
     initializer-list.  If the initializer can initialize a member,
     the member is initialized.  Otherwise, if the member is itself a
     non-empty subaggregate, brace elision is assumed and the
     initializer is considered for the initialization of the first
     member of the subaggregate.  */
  if ((TREE_CODE (init) != CONSTRUCTOR || COMPOUND_LITERAL_P (init))
      /* But don't try this for the first initializer, since that would be
	 looking through the outermost braces; A a2 = { a1 }; is not a
	 valid aggregate initialization.  */
      && !first_initializer_p
      && (same_type_ignoring_top_level_qualifiers_p (type, TREE_TYPE (init))
	  || can_convert_arg (type, TREE_TYPE (init), init, LOOKUP_NORMAL,
			      complain)))
    {
      d->cur++;
      return init;
    }

  /* [dcl.init.string]

      A char array (whether plain char, signed char, or unsigned char)
      can be initialized by a string-literal (optionally enclosed in
      braces); a wchar_t array can be initialized by a wide
      string-literal (optionally enclosed in braces).  */
  if (TREE_CODE (type) == ARRAY_TYPE
      && char_type_p (TYPE_MAIN_VARIANT (TREE_TYPE (type))))
    {
      tree str_init = init;
      tree stripped_str_init = stripped_init;
      reshape_iter stripd = {};

      /* Strip one level of braces if and only if they enclose a single
	 element (as allowed by [dcl.init.string]).  */
      if (!first_initializer_p
	  && TREE_CODE (stripped_str_init) == CONSTRUCTOR
	  && CONSTRUCTOR_NELTS (stripped_str_init) == 1)
	{
	  stripd.cur = CONSTRUCTOR_ELT (stripped_str_init, 0);
	  str_init = stripd.cur->value;
	  stripped_str_init = tree_strip_any_location_wrapper (str_init);
	}

      /* If it's a string literal, then it's the initializer for the array
	 as a whole. Otherwise, continue with normal initialization for
	 array types (one value per array element).  */
      if (TREE_CODE (stripped_str_init) == STRING_CST)
	{
	  if ((first_initializer_p && has_designator_problem (d, complain))
	      || (stripd.cur && has_designator_problem (&stripd, complain)))
	    return error_mark_node;
	  d->cur++;
	  return str_init;
	}
    }

  /* The following cases are about aggregates. If we are not within a full
     initializer already, and there is not a CONSTRUCTOR, it means that there
     is a missing set of braces (that is, we are processing the case for
     which reshape_init exists).  */
  bool braces_elided_p = false;
  if (!first_initializer_p)
    {
      if (TREE_CODE (stripped_init) == CONSTRUCTOR)
	{
	  tree init_type = TREE_TYPE (init);
	  if (init_type && TYPE_PTRMEMFUNC_P (init_type))
	    /* There is no need to call reshape_init for pointer-to-member
	       function initializers, as they are always constructed correctly
	       by the front end.  Here we have e.g. {.__pfn=0B, .__delta=0},
	       which is missing outermost braces.  We should warn below, and
	       one of the routines below will wrap it in additional { }.  */;
	  /* For a nested compound literal, proceed to specialized routines,
	     to handle initialization of arrays and similar.  */
	  else if (COMPOUND_LITERAL_P (stripped_init))
	    gcc_assert (!BRACE_ENCLOSED_INITIALIZER_P (stripped_init));
	  /* If we have an unresolved designator, we need to find the member it
	     designates within TYPE, so proceed to the routines below.  For
	     FIELD_DECL or INTEGER_CST designators, we're already initializing
	     the designated element.  */
	  else if (d->cur->index
		   && TREE_CODE (d->cur->index) == IDENTIFIER_NODE)
	    /* Brace elision with designators is only permitted for anonymous
	       aggregates.  */
	    gcc_checking_assert (ANON_AGGR_TYPE_P (type));
	  /* A CONSTRUCTOR of the target's type is a previously
	     digested initializer.  */
	  else if (same_type_ignoring_top_level_qualifiers_p (type, init_type))
	    {
	      ++d->cur;
	      return init;
	    }
	  else
	    {
	      /* Something that hasn't been reshaped yet.  */
	      ++d->cur;
	      gcc_assert (BRACE_ENCLOSED_INITIALIZER_P (stripped_init));
	      return reshape_init (type, init, complain);
	    }
	}

      if (complain & tf_warning)
	warning (OPT_Wmissing_braces,
		 "missing braces around initializer for %qT",
		 type);
      braces_elided_p = true;
    }

  /* Dispatch to specialized routines.  */
  tree new_init;
  if (CLASS_TYPE_P (type))
    new_init = reshape_init_class (type, d, first_initializer_p, complain);
  else if (TREE_CODE (type) == ARRAY_TYPE)
    new_init = reshape_init_array (type, d, first_initializer_p, complain);
  else if (VECTOR_TYPE_P (type))
    new_init = reshape_init_vector (type, d, complain);
  else
    gcc_unreachable();

  if (braces_elided_p
      && TREE_CODE (new_init) == CONSTRUCTOR)
    CONSTRUCTOR_BRACES_ELIDED_P (new_init) = true;

  return new_init;
}

/* Undo the brace-elision allowed by [dcl.init.aggr] in a
   brace-enclosed aggregate initializer.

   INIT is the CONSTRUCTOR containing the list of initializers describing
   a brace-enclosed initializer for an entity of the indicated aggregate TYPE.
   It may not presently match the shape of the TYPE; for example:

     struct S { int a; int b; };
     struct S a[] = { 1, 2, 3, 4 };

   Here INIT will hold a vector of four elements, rather than a
   vector of two elements, each itself a vector of two elements.  This
   routine transforms INIT from the former form into the latter.  The
   revised CONSTRUCTOR node is returned.  */

tree
reshape_init (tree type, tree init, tsubst_flags_t complain)
{
  vec<constructor_elt, va_gc> *v;
  reshape_iter d;
  tree new_init;

  gcc_assert (BRACE_ENCLOSED_INITIALIZER_P (init));

  v = CONSTRUCTOR_ELTS (init);

  /* An empty constructor does not need reshaping, and it is always a valid
     initializer.  */
  if (vec_safe_is_empty (v))
    return init;

  /* Brace elision is not performed for a CONSTRUCTOR representing
     parenthesized aggregate initialization.  */
  if (CONSTRUCTOR_IS_PAREN_INIT (init))
    {
      tree elt = (*v)[0].value;
      /* If we're initializing a char array from a string-literal that is
	 enclosed in braces, unwrap it here.  */
      if (TREE_CODE (type) == ARRAY_TYPE
	  && vec_safe_length (v) == 1
	  && char_type_p (TYPE_MAIN_VARIANT (TREE_TYPE (type)))
	  && TREE_CODE (tree_strip_any_location_wrapper (elt)) == STRING_CST)
	return elt;
      return init;
    }

  /* Handle [dcl.init.list] direct-list-initialization from
     single element of enumeration with a fixed underlying type.  */
  if (is_direct_enum_init (type, init))
    {
      tree elt = CONSTRUCTOR_ELT (init, 0)->value;
      type = cv_unqualified (type);
      if (check_narrowing (ENUM_UNDERLYING_TYPE (type), elt, complain))
	{
	  warning_sentinel w (warn_useless_cast);
	  warning_sentinel w2 (warn_ignored_qualifiers);
	  return cp_build_c_cast (input_location, type, elt,
				  tf_warning_or_error);
	}
      else
	return error_mark_node;
    }

  /* Recurse on this CONSTRUCTOR.  */
  d.cur = &(*v)[0];
  d.end = d.cur + v->length ();

  new_init = reshape_init_r (type, &d, init, complain);
  if (new_init == error_mark_node)
    return error_mark_node;

  /* Make sure all the element of the constructor were used. Otherwise,
     issue an error about exceeding initializers.  */
  if (d.cur != d.end)
    {
      if (complain & tf_error)
	error ("too many initializers for %qT", type);
      return error_mark_node;
    }

  if (CONSTRUCTOR_IS_DIRECT_INIT (init)
      && BRACE_ENCLOSED_INITIALIZER_P (new_init))
    CONSTRUCTOR_IS_DIRECT_INIT (new_init) = true;
  if (CONSTRUCTOR_IS_DESIGNATED_INIT (init)
      && BRACE_ENCLOSED_INITIALIZER_P (new_init))
    CONSTRUCTOR_IS_DESIGNATED_INIT (new_init) = true;

  return new_init;
}

/* Verify array initializer.  Returns true if errors have been reported.  */

bool
check_array_initializer (tree decl, tree type, tree init)
{
  tree element_type = TREE_TYPE (type);

  /* Structured binding when initialized with an array type needs
     to have complete type.  */
  if (decl
      && DECL_DECOMPOSITION_P (decl)
      && !DECL_DECOMP_BASE (decl)
      && !COMPLETE_TYPE_P (type))
    {
      error_at (DECL_SOURCE_LOCATION (decl),
		"structured binding has incomplete type %qT", type);
      TREE_TYPE (decl) = error_mark_node;
      return true;
    }

  /* The array type itself need not be complete, because the
     initializer may tell us how many elements are in the array.
     But, the elements of the array must be complete.  */
  if (!COMPLETE_TYPE_P (complete_type (element_type)))
    {
      if (decl)
	error_at (DECL_SOURCE_LOCATION (decl),
		  "elements of array %q#D have incomplete type", decl);
      else
	error ("elements of array %q#T have incomplete type", type);
      return true;
    }

  location_t loc = (decl ? location_of (decl) : input_location);
  if (!verify_type_context (loc, TCTX_ARRAY_ELEMENT, element_type))
    return true;

  /* A compound literal can't have variable size.  */
  if (init && !decl
      && ((COMPLETE_TYPE_P (type) && !TREE_CONSTANT (TYPE_SIZE (type)))
	  || !TREE_CONSTANT (TYPE_SIZE (element_type))))
    {
      error ("variable-sized compound literal");
      return true;
    }
  return false;
}

/* Subroutine of check_initializer; args are passed down from that function.
   Set stmts_are_full_exprs_p to 1 across a call to build_aggr_init.  */

static tree
build_aggr_init_full_exprs (tree decl, tree init, int flags)
     
{
  gcc_assert (stmts_are_full_exprs_p ());
  return build_aggr_init (decl, init, flags, tf_warning_or_error);
}

/* Verify INIT (the initializer for DECL), and record the
   initialization in DECL_INITIAL, if appropriate.  CLEANUP is as for
   grok_reference_init.

   If the return value is non-NULL, it is an expression that must be
   evaluated dynamically to initialize DECL.  */

static tree
check_initializer (tree decl, tree init, int flags, vec<tree, va_gc> **cleanups)
{
  tree type;
  tree init_code = NULL;
  tree core_type;

  /* Things that are going to be initialized need to have complete
     type.  */
  TREE_TYPE (decl) = type = complete_type (TREE_TYPE (decl));

  if (DECL_HAS_VALUE_EXPR_P (decl))
    {
      /* A variable with DECL_HAS_VALUE_EXPR_P set is just a placeholder,
	 it doesn't have storage to be initialized.  */
      gcc_assert (init == NULL_TREE);
      return NULL_TREE;
    }

  if (type == error_mark_node)
    /* We will have already complained.  */
    return NULL_TREE;

  if (TREE_CODE (type) == ARRAY_TYPE)
    {
      if (check_array_initializer (decl, type, init))
	return NULL_TREE;
    }
  else if (!COMPLETE_TYPE_P (type))
    {
      error_at (DECL_SOURCE_LOCATION (decl),
		"%q#D has incomplete type", decl);
      TREE_TYPE (decl) = error_mark_node;
      return NULL_TREE;
    }
  else
    /* There is no way to make a variable-sized class type in GNU C++.  */
    gcc_assert (TREE_CONSTANT (TYPE_SIZE (type)));

  if (init && BRACE_ENCLOSED_INITIALIZER_P (init))
    {
      int init_len = CONSTRUCTOR_NELTS (init);
      if (SCALAR_TYPE_P (type))
	{
	  if (init_len == 0)
	    {
	      maybe_warn_cpp0x (CPP0X_INITIALIZER_LISTS);
	      init = build_zero_init (type, NULL_TREE, false);
	    }
	  else if (init_len != 1 && TREE_CODE (type) != COMPLEX_TYPE)
	    {
	      error_at (cp_expr_loc_or_loc (init, DECL_SOURCE_LOCATION (decl)),
			"scalar object %qD requires one element in "
			"initializer", decl);
	      TREE_TYPE (decl) = error_mark_node;
	      return NULL_TREE;
	    }
	}
    }

  if (TREE_CODE (decl) == CONST_DECL)
    {
      gcc_assert (!TYPE_REF_P (type));

      DECL_INITIAL (decl) = init;

      gcc_assert (init != NULL_TREE);
      init = NULL_TREE;
    }
  else if (!init && DECL_REALLY_EXTERN (decl))
    ;
  else if (init || type_build_ctor_call (type)
	   || TYPE_REF_P (type))
    {
      if (TYPE_REF_P (type))
	{
	  init = grok_reference_init (decl, type, init, flags);
	  flags |= LOOKUP_ALREADY_DIGESTED;
	}
      else if (!init)
	check_for_uninitialized_const_var (decl, /*constexpr_context_p=*/false,
					   tf_warning_or_error);
      /* Do not reshape constructors of vectors (they don't need to be
	 reshaped.  */
      else if (BRACE_ENCLOSED_INITIALIZER_P (init))
	{
	  if (is_std_init_list (type))
	    {
	      init = perform_implicit_conversion (type, init,
						  tf_warning_or_error);
	      flags |= LOOKUP_ALREADY_DIGESTED;
	    }
	  else if (TYPE_NON_AGGREGATE_CLASS (type))
	    {
	      /* Don't reshape if the class has constructors.  */
	      if (cxx_dialect == cxx98)
		error_at (cp_expr_loc_or_loc (init, DECL_SOURCE_LOCATION (decl)),
			  "in C++98 %qD must be initialized by "
			  "constructor, not by %<{...}%>",
			  decl);
	    }
	  else if (VECTOR_TYPE_P (type) && TYPE_VECTOR_OPAQUE (type))
	    {
	      error ("opaque vector types cannot be initialized");
	      init = error_mark_node;
	    }
	  else
	    {
	      init = reshape_init (type, init, tf_warning_or_error);
	      flags |= LOOKUP_NO_NARROWING;
	    }
	}
      /* [dcl.init] "Otherwise, if the destination type is an array, the object
	 is initialized as follows..."  So handle things like

	  int a[](1, 2, 3);

	 which is permitted in C++20 by P0960.  */
      else if (TREE_CODE (init) == TREE_LIST
	       && TREE_TYPE (init) == NULL_TREE
	       && TREE_CODE (type) == ARRAY_TYPE
	       && !DECL_DECOMPOSITION_P (decl)
	       && (cxx_dialect >= cxx20))
	init = do_aggregate_paren_init (init, type);
      else if (TREE_CODE (init) == TREE_LIST
	       && TREE_TYPE (init) != unknown_type_node
	       && !MAYBE_CLASS_TYPE_P (type))
	{
	  gcc_assert (TREE_CODE (decl) != RESULT_DECL);

	  /* We get here with code like `int a (2);' */
	  init = build_x_compound_expr_from_list (init, ELK_INIT,
						  tf_warning_or_error);
	}

      /* If DECL has an array type without a specific bound, deduce the
	 array size from the initializer.  */
      maybe_deduce_size_from_array_init (decl, init);
      type = TREE_TYPE (decl);
      if (type == error_mark_node)
	return NULL_TREE;

      if (((type_build_ctor_call (type) || CLASS_TYPE_P (type))
	   && !(flags & LOOKUP_ALREADY_DIGESTED)
	   && !(init && BRACE_ENCLOSED_INITIALIZER_P (init)
		&& CP_AGGREGATE_TYPE_P (type)
		&& (CLASS_TYPE_P (type)
		    /* The call to build_aggr_init below could end up
		       calling build_vec_init, which may break when we
		       are processing a template.  */
		    || processing_template_decl
		    || !TYPE_NEEDS_CONSTRUCTING (type)
		    || type_has_extended_temps (type))))
	  || (DECL_DECOMPOSITION_P (decl) && TREE_CODE (type) == ARRAY_TYPE))
	{
	  init_code = build_aggr_init_full_exprs (decl, init, flags);

	  /* A constructor call is a non-trivial initializer even if
	     it isn't explicitly written.  */
	  if (TREE_SIDE_EFFECTS (init_code))
	    DECL_NONTRIVIALLY_INITIALIZED_P (decl) = true;

	  /* If this is a constexpr initializer, expand_default_init will
	     have returned an INIT_EXPR rather than a CALL_EXPR.  In that
	     case, pull the initializer back out and pass it down into
	     store_init_value.  */
	  while (true)
	    {
	      if (TREE_CODE (init_code) == EXPR_STMT
		  || TREE_CODE (init_code) == STMT_EXPR
		  || TREE_CODE (init_code) == CONVERT_EXPR)
		init_code = TREE_OPERAND (init_code, 0);
	      else if (TREE_CODE (init_code) == BIND_EXPR)
		init_code = BIND_EXPR_BODY (init_code);
	      else
		break;
	    }
	  if (TREE_CODE (init_code) == INIT_EXPR)
	    {
	      /* In C++20, the call to build_aggr_init could have created
		 an INIT_EXPR with a CONSTRUCTOR as the RHS to handle
		 A(1, 2).  */
	      tree rhs = TREE_OPERAND (init_code, 1);
	      if (processing_template_decl && TREE_CODE (rhs) == TARGET_EXPR)
		/* Avoid leaking TARGET_EXPR into template trees.  */
		rhs = build_implicit_conv_flags (type, init, flags);
	      init = rhs;

	      init_code = NULL_TREE;
	      /* Don't call digest_init; it's unnecessary and will complain
		 about aggregate initialization of non-aggregate classes.  */
	      flags |= LOOKUP_ALREADY_DIGESTED;
	    }
	  else if (DECL_DECLARED_CONSTEXPR_P (decl)
		   || DECL_DECLARED_CONSTINIT_P (decl))
	    {
	      /* Declared constexpr or constinit, but no suitable initializer;
		 massage init appropriately so we can pass it into
		 store_init_value for the error.  */
	      tree new_init = NULL_TREE;
	      if (!processing_template_decl
		  && TREE_CODE (init_code) == CALL_EXPR)
		new_init = build_cplus_new (type, init_code, tf_none);
	      else if (CLASS_TYPE_P (type)
		       && (!init || TREE_CODE (init) == TREE_LIST))
		new_init = build_functional_cast (input_location, type,
						  init, tf_none);
	      if (new_init)
		{
		  init = new_init;
		  if (TREE_CODE (init) == TARGET_EXPR
		      && !(flags & LOOKUP_ONLYCONVERTING))
		    TARGET_EXPR_DIRECT_INIT_P (init) = true;
		}
	      init_code = NULL_TREE;
	    }
	  else
	    init = NULL_TREE;
	}

      if (init && TREE_CODE (init) != TREE_VEC)
	{
	  init_code = store_init_value (decl, init, cleanups, flags);

	  if (DECL_INITIAL (decl)
	      && TREE_CODE (DECL_INITIAL (decl)) == CONSTRUCTOR
	      && !vec_safe_is_empty (CONSTRUCTOR_ELTS (DECL_INITIAL (decl))))
	    {
	      tree elt = CONSTRUCTOR_ELTS (DECL_INITIAL (decl))->last ().value;
	      if (TREE_CODE (TREE_TYPE (elt)) == ARRAY_TYPE
		  && TYPE_SIZE (TREE_TYPE (elt)) == NULL_TREE)
		cp_complete_array_type (&TREE_TYPE (elt), elt, false);
	    }

	  if (pedantic && TREE_CODE (type) == ARRAY_TYPE
	      && DECL_INITIAL (decl)
	      && TREE_CODE (DECL_INITIAL (decl)) == STRING_CST
	      && PAREN_STRING_LITERAL_P (DECL_INITIAL (decl)))
	    warning_at (cp_expr_loc_or_loc (DECL_INITIAL (decl),
					 DECL_SOURCE_LOCATION (decl)),
			0, "array %qD initialized by parenthesized "
			"string literal %qE",
			decl, DECL_INITIAL (decl));
	  init = NULL_TREE;
	}
    }
  else
    {
      if (CLASS_TYPE_P (core_type = strip_array_types (type))
	  && (CLASSTYPE_READONLY_FIELDS_NEED_INIT (core_type)
	      || CLASSTYPE_REF_FIELDS_NEED_INIT (core_type)))
	diagnose_uninitialized_cst_or_ref_member (core_type, /*using_new=*/false,
						  /*complain=*/true);

      check_for_uninitialized_const_var (decl, /*constexpr_context_p=*/false,
					 tf_warning_or_error);
    }

  if (init && init != error_mark_node)
    init_code = build2 (INIT_EXPR, type, decl, init);

  if (init_code && !TREE_SIDE_EFFECTS (init_code)
      && init_code != error_mark_node)
    init_code = NULL_TREE;

  if (init_code)
    {
      /* We might have set these in cp_finish_decl.  */
      DECL_INITIALIZED_BY_CONSTANT_EXPRESSION_P (decl) = false;
      TREE_CONSTANT (decl) = false;
    }

  if (init_code
      && DECL_IN_AGGR_P (decl)
      && DECL_INITIALIZED_IN_CLASS_P (decl))
    {
      static int explained = 0;

      if (cxx_dialect < cxx11)
	error ("initializer invalid for static member with constructor");
      else if (cxx_dialect < cxx17)
	error ("non-constant in-class initialization invalid for static "
	       "member %qD", decl);
      else
	error ("non-constant in-class initialization invalid for non-inline "
	       "static member %qD", decl);
      if (!explained)
	{
	  inform (input_location,
		  "(an out of class initialization is required)");
	  explained = 1;
	}
      return NULL_TREE;
    }

  return init_code;
}

/* If DECL is not a local variable, give it RTL.  */

static void
make_rtl_for_nonlocal_decl (tree decl, tree init, const char* asmspec)
{
  int toplev = toplevel_bindings_p ();
  int defer_p;

  /* Set the DECL_ASSEMBLER_NAME for the object.  */
  if (asmspec)
    {
      /* The `register' keyword, when used together with an
	 asm-specification, indicates that the variable should be
	 placed in a particular register.  */
      if (VAR_P (decl) && DECL_REGISTER (decl))
	{
	  set_user_assembler_name (decl, asmspec);
	  DECL_HARD_REGISTER (decl) = 1;
	}
      else
	{
	  if (TREE_CODE (decl) == FUNCTION_DECL
	      && fndecl_built_in_p (decl, BUILT_IN_NORMAL))
	    set_builtin_user_assembler_name (decl, asmspec);
	  set_user_assembler_name (decl, asmspec);
	  if (DECL_LOCAL_DECL_P (decl))
	    if (auto ns_decl = DECL_LOCAL_DECL_ALIAS (decl))
	      /* We have to propagate the name to the ns-alias.
		 This is horrible, as we're affecting a
		 possibly-shared decl.  Again, a one-true-decl
		 model breaks down.  */
	      if (ns_decl != error_mark_node)
		set_user_assembler_name (ns_decl, asmspec);
	}
    }

  /* Handle non-variables up front.  */
  if (!VAR_P (decl))
    {
      rest_of_decl_compilation (decl, toplev, at_eof);
      return;
    }

  /* If we see a class member here, it should be a static data
     member.  */
  if (DECL_LANG_SPECIFIC (decl) && DECL_IN_AGGR_P (decl))
    {
      gcc_assert (TREE_STATIC (decl));
      /* An in-class declaration of a static data member should be
	 external; it is only a declaration, and not a definition.  */
      if (init == NULL_TREE)
	gcc_assert (DECL_EXTERNAL (decl)
		    || !TREE_PUBLIC (decl));
    }

  /* We don't create any RTL for local variables.  */
  if (DECL_FUNCTION_SCOPE_P (decl) && !TREE_STATIC (decl))
    return;

  /* We defer emission of local statics until the corresponding
     DECL_EXPR is expanded.  But with constexpr its function might never
     be expanded, so go ahead and tell cgraph about the variable now.  */
  defer_p = ((DECL_FUNCTION_SCOPE_P (decl)
	      && !var_in_maybe_constexpr_fn (decl))
	     || DECL_VIRTUAL_P (decl));

  /* Defer template instantiations.  */
  if (DECL_LANG_SPECIFIC (decl)
      && DECL_IMPLICIT_INSTANTIATION (decl))
    defer_p = 1;

  /* If we're not deferring, go ahead and assemble the variable.  */
  if (!defer_p)
    rest_of_decl_compilation (decl, toplev, at_eof);
}

/* walk_tree helper for wrap_temporary_cleanups, below.  */

static tree
wrap_cleanups_r (tree *stmt_p, int *walk_subtrees, void *data)
{
  /* Stop at types or full-expression boundaries.  */
  if (TYPE_P (*stmt_p)
      || TREE_CODE (*stmt_p) == CLEANUP_POINT_EXPR)
    {
      *walk_subtrees = 0;
      return NULL_TREE;
    }

  if (TREE_CODE (*stmt_p) == TARGET_EXPR)
    {
      tree guard = (tree)data;
      tree tcleanup = TARGET_EXPR_CLEANUP (*stmt_p);

      if (tcleanup && !CLEANUP_EH_ONLY (*stmt_p)
	  && !expr_noexcept_p (tcleanup, tf_none))
	{
	  tcleanup = build2 (TRY_CATCH_EXPR, void_type_node, tcleanup, guard);
	  /* Tell honor_protect_cleanup_actions to handle this as a separate
	     cleanup.  */
	  TRY_CATCH_IS_CLEANUP (tcleanup) = 1;
	  TARGET_EXPR_CLEANUP (*stmt_p) = tcleanup;
	}
    }

  return NULL_TREE;
}

/* We're initializing a local variable which has a cleanup GUARD.  If there
   are any temporaries used in the initializer INIT of this variable, we
   need to wrap their cleanups with TRY_CATCH_EXPR (, GUARD) so that the
   variable will be cleaned up properly if one of them throws.

   Unfortunately, there's no way to express this properly in terms of
   nesting, as the regions for the temporaries overlap the region for the
   variable itself; if there are two temporaries, the variable needs to be
   the first thing destroyed if either of them throws.  However, we only
   want to run the variable's cleanup if it actually got constructed.  So
   we need to guard the temporary cleanups with the variable's cleanup if
   they are run on the normal path, but not if they are run on the
   exceptional path.  We implement this by telling
   honor_protect_cleanup_actions to strip the variable cleanup from the
   exceptional path.

   Another approach could be to make the variable cleanup region enclose
   initialization, but depend on a flag to indicate that the variable is
   initialized; that's effectively what we do for arrays.  But the current
   approach works fine for non-arrays, and has no code overhead in the usual
   case where the temporary destructors are noexcept.  */

static void
wrap_temporary_cleanups (tree init, tree guard)
{
  if (TREE_CODE (guard) == BIND_EXPR)
    {
      /* An array cleanup region already encloses any temporary cleanups,
	 don't wrap it around them again.  */
      gcc_checking_assert (BIND_EXPR_VEC_DTOR (guard));
      return;
    }
  cp_walk_tree_without_duplicates (&init, wrap_cleanups_r, (void *)guard);
}

/* Generate code to initialize DECL (a local variable).  */

static void
initialize_local_var (tree decl, tree init)
{
  tree type = TREE_TYPE (decl);
  tree cleanup;
  int already_used;

  gcc_assert (VAR_P (decl)
	      || TREE_CODE (decl) == RESULT_DECL);
  gcc_assert (!TREE_STATIC (decl));

  if (DECL_SIZE (decl) == NULL_TREE)
    {
      /* If we used it already as memory, it must stay in memory.  */
      DECL_INITIAL (decl) = NULL_TREE;
      TREE_ADDRESSABLE (decl) = TREE_USED (decl);
      return;
    }

  if (type == error_mark_node)
    return;

  /* Compute and store the initial value.  */
  already_used = TREE_USED (decl) || TREE_USED (type);
  if (TREE_USED (type))
    DECL_READ_P (decl) = 1;

  /* Generate a cleanup, if necessary.  */
  cleanup = cxx_maybe_build_cleanup (decl, tf_warning_or_error);

  /* Perform the initialization.  */
  if (init)
    {
      tree rinit = (TREE_CODE (init) == INIT_EXPR
		    ? TREE_OPERAND (init, 1) : NULL_TREE);
      if (rinit && !TREE_SIDE_EFFECTS (rinit)
	  && TREE_OPERAND (init, 0) == decl)
	{
	  /* Stick simple initializers in DECL_INITIAL so that
	     -Wno-init-self works (c++/34772).  */
	  DECL_INITIAL (decl) = rinit;

	  if (warn_init_self && TYPE_REF_P (type))
	    {
	      STRIP_NOPS (rinit);
	      if (rinit == decl)
		warning_at (DECL_SOURCE_LOCATION (decl),
			    OPT_Winit_self,
			    "reference %qD is initialized with itself", decl);
	    }
	}
      else
	{
	  int saved_stmts_are_full_exprs_p;

	  /* If we're only initializing a single object, guard the
	     destructors of any temporaries used in its initializer with
	     its destructor.  */
	  if (cleanup)
	    wrap_temporary_cleanups (init, cleanup);

	  gcc_assert (building_stmt_list_p ());
	  saved_stmts_are_full_exprs_p = stmts_are_full_exprs_p ();
	  current_stmt_tree ()->stmts_are_full_exprs_p = 1;
	  finish_expr_stmt (init);
	  current_stmt_tree ()->stmts_are_full_exprs_p =
	    saved_stmts_are_full_exprs_p;
	}
    }

  /* Set this to 0 so we can tell whether an aggregate which was
     initialized was ever used.  Don't do this if it has a
     destructor, so we don't complain about the 'resource
     allocation is initialization' idiom.  Now set
     attribute((unused)) on types so decls of that type will be
     marked used. (see TREE_USED, above.)  */
  if (TYPE_NEEDS_CONSTRUCTING (type)
      && ! already_used
      && TYPE_HAS_TRIVIAL_DESTRUCTOR (type)
      && DECL_NAME (decl))
    TREE_USED (decl) = 0;
  else if (already_used)
    TREE_USED (decl) = 1;

  if (cleanup)
    finish_decl_cleanup (decl, cleanup);
}

/* DECL is a VAR_DECL for a compiler-generated variable with static
   storage duration (like a virtual table) whose initializer is a
   compile-time constant.  Initialize the variable and provide it to the
   back end.  */

void
initialize_artificial_var (tree decl, vec<constructor_elt, va_gc> *v)
{
  tree init;
  gcc_assert (DECL_ARTIFICIAL (decl));
  init = build_constructor (TREE_TYPE (decl), v);
  gcc_assert (TREE_CODE (init) == CONSTRUCTOR);
  DECL_INITIAL (decl) = init;
  DECL_INITIALIZED_P (decl) = 1;
  /* Mark the decl as constexpr so that we can access its content
     at compile time.  */
  DECL_INITIALIZED_BY_CONSTANT_EXPRESSION_P (decl) = true;
  DECL_DECLARED_CONSTEXPR_P (decl) = true;
  determine_visibility (decl);
  layout_var_decl (decl);
  maybe_commonize_var (decl);
  make_rtl_for_nonlocal_decl (decl, init, /*asmspec=*/NULL);
}

/* INIT is the initializer for a variable, as represented by the
   parser.  Returns true iff INIT is value-dependent.  */

static bool
value_dependent_init_p (tree init)
{
  if (TREE_CODE (init) == TREE_LIST)
    /* A parenthesized initializer, e.g.: int i (3, 2); ? */
    return any_value_dependent_elements_p (init);
  else if (TREE_CODE (init) == CONSTRUCTOR)
  /* A brace-enclosed initializer, e.g.: int i = { 3 }; ? */
    {
      if (dependent_type_p (TREE_TYPE (init)))
	return true;

      vec<constructor_elt, va_gc> *elts;
      size_t nelts;
      size_t i;

      elts = CONSTRUCTOR_ELTS (init);
      nelts = vec_safe_length (elts);
      for (i = 0; i < nelts; ++i)
	if (value_dependent_init_p ((*elts)[i].value))
	  return true;
    }
  else
    /* It must be a simple expression, e.g., int i = 3;  */
    return value_dependent_expression_p (init);
  
  return false;
}

// Returns true if a DECL is VAR_DECL with the concept specifier.
static inline bool
is_concept_var (tree decl)
{
  return (VAR_P (decl)
	  // Not all variables have DECL_LANG_SPECIFIC.
          && DECL_LANG_SPECIFIC (decl)
          && DECL_DECLARED_CONCEPT_P (decl));
}

/* A helper function to be called via walk_tree.  If any label exists
   under *TP, it is (going to be) forced.  Set has_forced_label_in_static.  */

static tree
notice_forced_label_r (tree *tp, int *walk_subtrees, void *)
{
  if (TYPE_P (*tp))
    *walk_subtrees = 0;
  if (TREE_CODE (*tp) == LABEL_DECL)
    cfun->has_forced_label_in_static = 1;
  return NULL_TREE;
}

/* Return true if DECL has either a trivial destructor, or for C++20
   is constexpr and has a constexpr destructor.  */

static bool
decl_maybe_constant_destruction (tree decl, tree type)
{
  return (TYPE_HAS_TRIVIAL_DESTRUCTOR (type)
	  || (cxx_dialect >= cxx20
	      && VAR_P (decl)
	      && DECL_DECLARED_CONSTEXPR_P (decl)
	      && type_has_constexpr_destructor (strip_array_types (type))));
}

static tree declare_simd_adjust_this (tree *, int *, void *);

/* Helper function of omp_declare_variant_finalize.  Finalize one
   "omp declare variant base" attribute.  Return true if it should be
   removed.  */

static bool
omp_declare_variant_finalize_one (tree decl, tree attr)
{
  if (TREE_CODE (TREE_TYPE (decl)) == METHOD_TYPE)
    {
      walk_tree (&TREE_VALUE (TREE_VALUE (attr)), declare_simd_adjust_this,
		 DECL_ARGUMENTS (decl), NULL);
      walk_tree (&TREE_PURPOSE (TREE_VALUE (attr)), declare_simd_adjust_this,
		 DECL_ARGUMENTS (decl), NULL);
    }

  tree ctx = TREE_VALUE (TREE_VALUE (attr));
  tree simd = omp_get_context_selector (ctx, "construct", "simd");
  if (simd)
    {
      TREE_VALUE (simd)
	= c_omp_declare_simd_clauses_to_numbers (DECL_ARGUMENTS (decl),
						 TREE_VALUE (simd));
      /* FIXME, adjusting simd args unimplemented.  */
      return true;
    }

  tree chain = TREE_CHAIN (TREE_VALUE (attr));
  location_t varid_loc
    = cp_expr_loc_or_input_loc (TREE_PURPOSE (TREE_CHAIN (chain)));
  location_t match_loc = cp_expr_loc_or_input_loc (TREE_PURPOSE (chain));
  cp_id_kind idk = (cp_id_kind) tree_to_uhwi (TREE_VALUE (chain));
  tree variant = TREE_PURPOSE (TREE_VALUE (attr));

  location_t save_loc = input_location;
  input_location = varid_loc;

  releasing_vec args;
  tree parm = DECL_ARGUMENTS (decl);
  if (TREE_CODE (TREE_TYPE (decl)) == METHOD_TYPE)
    parm = DECL_CHAIN (parm);
  for (; parm; parm = DECL_CHAIN (parm))
    if (type_dependent_expression_p (parm))
      vec_safe_push (args, build_constructor (TREE_TYPE (parm), NULL));
    else if (MAYBE_CLASS_TYPE_P (TREE_TYPE (parm)))
      vec_safe_push (args, build_local_temp (TREE_TYPE (parm)));
    else
      vec_safe_push (args, build_zero_cst (TREE_TYPE (parm)));

  bool koenig_p = false;
  if (idk == CP_ID_KIND_UNQUALIFIED || idk == CP_ID_KIND_TEMPLATE_ID)
    {
      if (identifier_p (variant)
	  /* In C++20, we may need to perform ADL for a template
	     name.  */
	  || (TREE_CODE (variant) == TEMPLATE_ID_EXPR
	      && identifier_p (TREE_OPERAND (variant, 0))))
	{
	  if (!args->is_empty ())
	    {
	      koenig_p = true;
	      if (!any_type_dependent_arguments_p (args))
		variant = perform_koenig_lookup (variant, args,
						 tf_warning_or_error);
	    }
	  else
	    variant = unqualified_fn_lookup_error (variant);
	}
      else if (!args->is_empty () && is_overloaded_fn (variant))
	{
	  tree fn = get_first_fn (variant);
	  fn = STRIP_TEMPLATE (fn);
	  if (!((TREE_CODE (fn) == USING_DECL && DECL_DEPENDENT_P (fn))
		 || DECL_FUNCTION_MEMBER_P (fn)
		 || DECL_LOCAL_DECL_P (fn)))
	    {
	      koenig_p = true;
	      if (!any_type_dependent_arguments_p (args))
		variant = perform_koenig_lookup (variant, args,
						 tf_warning_or_error);
	    }
	}
    }

  if (idk == CP_ID_KIND_QUALIFIED)
    variant = finish_call_expr (variant, &args, /*disallow_virtual=*/true,
				koenig_p, tf_warning_or_error);
  else
    variant = finish_call_expr (variant, &args, /*disallow_virtual=*/false,
				koenig_p, tf_warning_or_error);
  if (variant == error_mark_node && !processing_template_decl)
    return true;

  variant = cp_get_callee_fndecl_nofold (variant);
  input_location = save_loc;

  if (variant)
    {
      const char *varname = IDENTIFIER_POINTER (DECL_NAME (variant));
      if (!comptypes (TREE_TYPE (decl), TREE_TYPE (variant), 0))
	{
	  error_at (varid_loc, "variant %qD and base %qD have incompatible "
			       "types", variant, decl);
	  return true;
	}
      if (fndecl_built_in_p (variant)
	  && (startswith (varname, "__builtin_")
	      || startswith (varname, "__sync_")
	      || startswith (varname, "__atomic_")))
	{
	  error_at (varid_loc, "variant %qD is a built-in", variant);
	  return true;
	}
      else
	{
	  tree construct = omp_get_context_selector (ctx, "construct", NULL);
	  omp_mark_declare_variant (match_loc, variant, construct);
	  if (!omp_context_selector_matches (ctx))
	    return true;
	  TREE_PURPOSE (TREE_VALUE (attr)) = variant;
	}
    }
  else if (!processing_template_decl)
    {
      error_at (varid_loc, "could not find variant declaration");
      return true;
    }

  return false;
}

/* Helper function, finish up "omp declare variant base" attribute
   now that there is a DECL.  ATTR is the first "omp declare variant base"
   attribute.  */

void
omp_declare_variant_finalize (tree decl, tree attr)
{
  size_t attr_len = strlen ("omp declare variant base");
  tree *list = &DECL_ATTRIBUTES (decl);
  bool remove_all = false;
  location_t match_loc = DECL_SOURCE_LOCATION (decl);
  if (TREE_CHAIN (TREE_VALUE (attr))
      && TREE_PURPOSE (TREE_CHAIN (TREE_VALUE (attr)))
      && EXPR_HAS_LOCATION (TREE_PURPOSE (TREE_CHAIN (TREE_VALUE (attr)))))
    match_loc = EXPR_LOCATION (TREE_PURPOSE (TREE_CHAIN (TREE_VALUE (attr))));
  if (DECL_CONSTRUCTOR_P (decl))
    {
      error_at (match_loc, "%<declare variant%> on constructor %qD", decl);
      remove_all = true;
    }
  else if (DECL_DESTRUCTOR_P (decl))
    {
      error_at (match_loc, "%<declare variant%> on destructor %qD", decl);
      remove_all = true;
    }
  else if (DECL_DEFAULTED_FN (decl))
    {
      error_at (match_loc, "%<declare variant%> on defaulted %qD", decl);
      remove_all = true;
    }
  else if (DECL_DELETED_FN (decl))
    {
      error_at (match_loc, "%<declare variant%> on deleted %qD", decl);
      remove_all = true;
    }
  else if (DECL_VIRTUAL_P (decl))
    {
      error_at (match_loc, "%<declare variant%> on virtual %qD", decl);
      remove_all = true;
    }
  /* This loop is like private_lookup_attribute, except that it works
     with tree * rather than tree, as we might want to remove the
     attributes that are diagnosed as errorneous.  */
  while (*list)
    {
      tree attr = get_attribute_name (*list);
      size_t ident_len = IDENTIFIER_LENGTH (attr);
      if (cmp_attribs ("omp declare variant base", attr_len,
		       IDENTIFIER_POINTER (attr), ident_len))
	{
	  if (remove_all || omp_declare_variant_finalize_one (decl, *list))
	    {
	      *list = TREE_CHAIN (*list);
	      continue;
	    }
	}
      list = &TREE_CHAIN (*list);
    }
}

/* Finish processing of a declaration;
   install its line number and initial value.
   If the length of an array type is not known before,
   it must be determined now, from the initial value, or it is an error.

   INIT is the initializer (if any) for DECL.  If INIT_CONST_EXPR_P is
   true, then INIT is an integral constant expression.

   FLAGS is LOOKUP_ONLYCONVERTING if the = init syntax was used, else 0
   if the (init) syntax was used.  */

void
cp_finish_decl (tree decl, tree init, bool init_const_expr_p,
		tree asmspec_tree, int flags)
{
  tree type;
  vec<tree, va_gc> *cleanups = NULL;
  const char *asmspec = NULL;
  int was_readonly = 0;
  bool var_definition_p = false;
  tree auto_node;

  if (decl == error_mark_node)
    return;
  else if (! decl)
    {
      if (init)
	error ("assignment (not initialization) in declaration");
      return;
    }

  gcc_assert (TREE_CODE (decl) != RESULT_DECL);
  /* Parameters are handled by store_parm_decls, not cp_finish_decl.  */
  gcc_assert (TREE_CODE (decl) != PARM_DECL);

  type = TREE_TYPE (decl);
  if (type == error_mark_node)
    return;

  if (VAR_P (decl) && is_copy_initialization (init))
    flags |= LOOKUP_ONLYCONVERTING;

  /* Warn about register storage specifiers except when in GNU global
     or local register variable extension.  */
  if (VAR_P (decl) && DECL_REGISTER (decl) && asmspec_tree == NULL_TREE)
    {
      if (cxx_dialect >= cxx17)
	pedwarn (DECL_SOURCE_LOCATION (decl), OPT_Wregister,
		 "ISO C++17 does not allow %<register%> storage "
		 "class specifier");
      else
	warning_at (DECL_SOURCE_LOCATION (decl), OPT_Wregister,
		    "%<register%> storage class specifier used");
    }

  /* If a name was specified, get the string.  */
  if (at_namespace_scope_p ())
    asmspec_tree = maybe_apply_renaming_pragma (decl, asmspec_tree);
  if (asmspec_tree && asmspec_tree != error_mark_node)
    asmspec = TREE_STRING_POINTER (asmspec_tree);

  bool in_class_decl
    = (current_class_type
       && CP_DECL_CONTEXT (decl) == current_class_type
       && TYPE_BEING_DEFINED (current_class_type)
       && !CLASSTYPE_TEMPLATE_INSTANTIATION (current_class_type));

  if (in_class_decl
      && (DECL_INITIAL (decl) || init))
    DECL_INITIALIZED_IN_CLASS_P (decl) = 1;

  if (TREE_CODE (decl) != FUNCTION_DECL
      && (auto_node = type_uses_auto (type)))
    {
      tree d_init;
      if (init == NULL_TREE)
	{
	  if (DECL_LANG_SPECIFIC (decl)
	      && DECL_TEMPLATE_INSTANTIATION (decl)
	      && !DECL_TEMPLATE_INSTANTIATED (decl))
	    {
	      /* init is null because we're deferring instantiating the
		 initializer until we need it.  Well, we need it now.  */
	      instantiate_decl (decl, /*defer_ok*/true, /*expl*/false);
	      return;
	    }

	  gcc_assert (CLASS_PLACEHOLDER_TEMPLATE (auto_node));
	}
      d_init = init;
      if (d_init)
	{
	  if (TREE_CODE (d_init) == TREE_LIST
	      && !CLASS_PLACEHOLDER_TEMPLATE (auto_node))
	    d_init = build_x_compound_expr_from_list (d_init, ELK_INIT,
						      tf_warning_or_error);
	  d_init = resolve_nondeduced_context (d_init, tf_warning_or_error);
	  /* Force auto deduction now.  Use tf_none to avoid redundant warnings
	     on deprecated-14.C.  */
	  mark_single_function (d_init, tf_none);
	}
      enum auto_deduction_context adc = adc_variable_type;
      if (VAR_P (decl) && DECL_DECOMPOSITION_P (decl))
	adc = adc_decomp_type;
      tree outer_targs = NULL_TREE;
      if (PLACEHOLDER_TYPE_CONSTRAINTS_INFO (auto_node)
	  && VAR_P (decl)
	  && DECL_LANG_SPECIFIC (decl)
	  && DECL_TEMPLATE_INFO (decl)
	  && !DECL_FUNCTION_SCOPE_P (decl))
	/* The outer template arguments might be needed for satisfaction.
	   (For function scope variables, do_auto_deduction will obtain the
	   outer template arguments from current_function_decl.)  */
	outer_targs = DECL_TI_ARGS (decl);
      type = TREE_TYPE (decl) = do_auto_deduction (type, d_init, auto_node,
						   tf_warning_or_error, adc,
						   outer_targs, flags);
      if (type == error_mark_node)
	return;
      if (TREE_CODE (type) == FUNCTION_TYPE)
	{
	  error ("initializer for %<decltype(auto) %D%> has function type; "
		 "did you forget the %<()%>?", decl);
	  TREE_TYPE (decl) = error_mark_node;
	  return;
	}
      cp_apply_type_quals_to_decl (cp_type_quals (type), decl);
    }

  if (ensure_literal_type_for_constexpr_object (decl) == error_mark_node)
    {
      DECL_DECLARED_CONSTEXPR_P (decl) = 0;
      if (VAR_P (decl) && DECL_CLASS_SCOPE_P (decl))
	{
	  init = NULL_TREE;
	  DECL_EXTERNAL (decl) = 1;
	}
    }

  if (VAR_P (decl)
      && DECL_CLASS_SCOPE_P (decl)
      && verify_type_context (DECL_SOURCE_LOCATION (decl),
			      TCTX_STATIC_STORAGE, type)
      && DECL_INITIALIZED_IN_CLASS_P (decl))
    check_static_variable_definition (decl, type);

  if (!processing_template_decl && VAR_P (decl) && is_global_var (decl))
    {
      type_context_kind context = (DECL_THREAD_LOCAL_P (decl)
				   ? TCTX_THREAD_STORAGE
				   : TCTX_STATIC_STORAGE);
      verify_type_context (input_location, context, TREE_TYPE (decl));
    }

  if (init && TREE_CODE (decl) == FUNCTION_DECL)
    {
      tree clone;
      if (init == ridpointers[(int)RID_DELETE])
	{
	  /* FIXME check this is 1st decl.  */
	  DECL_DELETED_FN (decl) = 1;
	  DECL_DECLARED_INLINE_P (decl) = 1;
	  DECL_INITIAL (decl) = error_mark_node;
	  FOR_EACH_CLONE (clone, decl)
	    {
	      DECL_DELETED_FN (clone) = 1;
	      DECL_DECLARED_INLINE_P (clone) = 1;
	      DECL_INITIAL (clone) = error_mark_node;
	    }
	  init = NULL_TREE;
	}
      else if (init == ridpointers[(int)RID_DEFAULT])
	{
	  if (defaultable_fn_check (decl))
	    DECL_DEFAULTED_FN (decl) = 1;
	  else
	    DECL_INITIAL (decl) = NULL_TREE;
	}
    }

  if (init && VAR_P (decl))
    {
      DECL_NONTRIVIALLY_INITIALIZED_P (decl) = 1;
      /* If DECL is a reference, then we want to know whether init is a
	 reference constant; init_const_expr_p as passed tells us whether
	 it's an rvalue constant.  */
      if (TYPE_REF_P (type))
	init_const_expr_p = potential_constant_expression (init);
      if (init_const_expr_p)
	{
	  /* Set these flags now for templates.  We'll update the flags in
	     store_init_value for instantiations.  */
	  DECL_INITIALIZED_BY_CONSTANT_EXPRESSION_P (decl) = 1;
	  if (decl_maybe_constant_var_p (decl)
	      /* FIXME setting TREE_CONSTANT on refs breaks the back end.  */
	      && !TYPE_REF_P (type))
	    TREE_CONSTANT (decl) = 1;
	}
      /* This is handled mostly by gimplify.cc, but we have to deal with
	 not warning about int x = x; as it is a GCC extension to turn off
	 this warning but only if warn_init_self is zero.  */
      if (!DECL_EXTERNAL (decl)
	  && !TREE_STATIC (decl)
	  && decl == tree_strip_any_location_wrapper (init)
	  && !warning_enabled_at (DECL_SOURCE_LOCATION (decl), OPT_Winit_self))
	suppress_warning (decl, OPT_Winit_self);
    }

  if (flag_openmp
      && TREE_CODE (decl) == FUNCTION_DECL
      /* #pragma omp declare variant on methods handled in finish_struct
	 instead.  */
      && (!DECL_NONSTATIC_MEMBER_FUNCTION_P (decl)
	  || COMPLETE_TYPE_P (DECL_CONTEXT (decl))))
    if (tree attr = lookup_attribute ("omp declare variant base",
				      DECL_ATTRIBUTES (decl)))
      omp_declare_variant_finalize (decl, attr);

  if (processing_template_decl)
    {
      bool type_dependent_p;

      /* Add this declaration to the statement-tree.  */
      if (at_function_scope_p ())
	add_decl_expr (decl);

      type_dependent_p = dependent_type_p (type);

      if (check_for_bare_parameter_packs (init))
	{
	  init = NULL_TREE;
	  DECL_INITIAL (decl) = NULL_TREE;
	}

      /* Generally, initializers in templates are expanded when the
	 template is instantiated.  But, if DECL is a variable constant
	 then it can be used in future constant expressions, so its value
	 must be available. */

      bool dep_init = false;

      if (!VAR_P (decl) || type_dependent_p)
	/* We can't do anything if the decl has dependent type.  */;
      else if (!init && is_concept_var (decl))
	{
	  error ("variable concept has no initializer");
	  init = boolean_true_node;
	}
      else if (init
	       && (init_const_expr_p || DECL_DECLARED_CONSTEXPR_P (decl))
	       && !TYPE_REF_P (type)
	       && decl_maybe_constant_var_p (decl)
	       && !(dep_init = value_dependent_init_p (init)))
	{
	  /* This variable seems to be a non-dependent constant, so process
	     its initializer.  If check_initializer returns non-null the
	     initialization wasn't constant after all.  */
	  tree init_code;
	  cleanups = make_tree_vector ();
	  init_code = check_initializer (decl, init, flags, &cleanups);
	  if (init_code == NULL_TREE)
	    init = NULL_TREE;
	  release_tree_vector (cleanups);
	}
      else
	{
	  gcc_assert (!DECL_PRETTY_FUNCTION_P (decl));
	  /* Try to deduce array size.  */
	  maybe_deduce_size_from_array_init (decl, init);
	  /* And complain about multiple initializers.  */
	  if (init && TREE_CODE (init) == TREE_LIST && TREE_CHAIN (init)
	      && !MAYBE_CLASS_TYPE_P (type))
	    init = build_x_compound_expr_from_list (init, ELK_INIT,
						    tf_warning_or_error);
	}

      if (init)
	DECL_INITIAL (decl) = init;

      if (dep_init)
	{
	  retrofit_lang_decl (decl);
	  SET_DECL_DEPENDENT_INIT_P (decl, true);
	}

      if (VAR_P (decl) && DECL_REGISTER (decl) && asmspec)
	{
	  set_user_assembler_name (decl, asmspec);
	  DECL_HARD_REGISTER (decl) = 1;
	}
      return;
    }

  /* Just store non-static data member initializers for later.  */
  if (init && TREE_CODE (decl) == FIELD_DECL)
    DECL_INITIAL (decl) = init;

  /* Take care of TYPE_DECLs up front.  */
  if (TREE_CODE (decl) == TYPE_DECL)
    {
      if (type != error_mark_node
	  && MAYBE_CLASS_TYPE_P (type) && DECL_NAME (decl))
	{
	  if (TREE_TYPE (DECL_NAME (decl)) && TREE_TYPE (decl) != type)
	    warning (0, "shadowing previous type declaration of %q#D", decl);
	  set_identifier_type_value (DECL_NAME (decl), decl);
	}

      /* If we have installed this as the canonical typedef for this
	 type, and that type has not been defined yet, delay emitting
	 the debug information for it, as we will emit it later.  */
      if (TYPE_MAIN_DECL (TREE_TYPE (decl)) == decl
	  && !COMPLETE_TYPE_P (TREE_TYPE (decl)))
	TYPE_DECL_SUPPRESS_DEBUG (decl) = 1;

      rest_of_decl_compilation (decl, DECL_FILE_SCOPE_P (decl),
				at_eof);
      return;
    }

  /* A reference will be modified here, as it is initialized.  */
  if (! DECL_EXTERNAL (decl)
      && TREE_READONLY (decl)
      && TYPE_REF_P (type))
    {
      was_readonly = 1;
      TREE_READONLY (decl) = 0;
    }

  /* This needs to happen before extend_ref_init_temps.  */
  if (VAR_OR_FUNCTION_DECL_P (decl))
    {
      if (VAR_P (decl))
	maybe_commonize_var (decl);
      determine_visibility (decl);
    }

  if (VAR_P (decl))
    {
      duration_kind dk = decl_storage_duration (decl);
      /* [dcl.constinit]/1 "The constinit specifier shall be applied
	 only to a declaration of a variable with static or thread storage
	 duration."  */
      if (DECL_DECLARED_CONSTINIT_P (decl)
	  && !(dk == dk_thread || dk == dk_static))
	{
	  error_at (DECL_SOURCE_LOCATION (decl),
		    "%<constinit%> can only be applied to a variable with "
		    "static or thread storage duration");
	  return;
	}

      /* If this is a local variable that will need a mangled name,
	 register it now.  We must do this before processing the
	 initializer for the variable, since the initialization might
	 require a guard variable, and since the mangled name of the
	 guard variable will depend on the mangled name of this
	 variable.  */
      if (DECL_FUNCTION_SCOPE_P (decl)
	  && TREE_STATIC (decl)
	  && !DECL_ARTIFICIAL (decl))
	{
	  /* The variable holding an anonymous union will have had its
	     discriminator set in finish_anon_union, after which it's
	     NAME will have been cleared.  */
	  if (DECL_NAME (decl))
	    determine_local_discriminator (decl);
	  /* Normally has_forced_label_in_static is set during GIMPLE
	     lowering, but [cd]tors are never actually compiled directly.
	     We need to set this early so we can deal with the label
	     address extension.  */
	  if ((DECL_CONSTRUCTOR_P (current_function_decl)
	       || DECL_DESTRUCTOR_P (current_function_decl))
	      && init)
	    {
	      walk_tree (&init, notice_forced_label_r, NULL, NULL);
	      add_local_decl (cfun, decl);
	    }
	  /* And make sure it's in the symbol table for
	     c_parse_final_cleanups to find.  */
	  varpool_node::get_create (decl);
	}

      /* Convert the initializer to the type of DECL, if we have not
	 already initialized DECL.  */
      if (!DECL_INITIALIZED_P (decl)
	  /* If !DECL_EXTERNAL then DECL is being defined.  In the
	     case of a static data member initialized inside the
	     class-specifier, there can be an initializer even if DECL
	     is *not* defined.  */
	  && (!DECL_EXTERNAL (decl) || init))
	{
	  cleanups = make_tree_vector ();
	  init = check_initializer (decl, init, flags, &cleanups);

	  /* Handle:

	     [dcl.init]

	     The memory occupied by any object of static storage
	     duration is zero-initialized at program startup before
	     any other initialization takes place.

	     We cannot create an appropriate initializer until after
	     the type of DECL is finalized.  If DECL_INITIAL is set,
	     then the DECL is statically initialized, and any
	     necessary zero-initialization has already been performed.  */
	  if (TREE_STATIC (decl) && !DECL_INITIAL (decl))
	    DECL_INITIAL (decl) = build_zero_init (TREE_TYPE (decl),
						   /*nelts=*/NULL_TREE,
						   /*static_storage_p=*/true);
	  /* Remember that the initialization for this variable has
	     taken place.  */
	  DECL_INITIALIZED_P (decl) = 1;
	  /* This declaration is the definition of this variable,
	     unless we are initializing a static data member within
	     the class specifier.  */
	  if (!DECL_EXTERNAL (decl))
	    var_definition_p = true;
	}
      /* If the variable has an array type, lay out the type, even if
	 there is no initializer.  It is valid to index through the
	 array, and we must get TYPE_ALIGN set correctly on the array
	 type.  */
      else if (TREE_CODE (type) == ARRAY_TYPE)
	layout_type (type);

      if (TREE_STATIC (decl)
	  && !at_function_scope_p ()
	  && current_function_decl == NULL)
	/* So decl is a global variable or a static member of a
	   non local class. Record the types it uses
	   so that we can decide later to emit debug info for them.  */
	record_types_used_by_current_var_decl (decl);
    }

  /* Add this declaration to the statement-tree.  This needs to happen
     after the call to check_initializer so that the DECL_EXPR for a
     reference temp is added before the DECL_EXPR for the reference itself.  */
  if (DECL_FUNCTION_SCOPE_P (decl))
    {
      /* If we're building a variable sized type, and we might be
	 reachable other than via the top of the current binding
	 level, then create a new BIND_EXPR so that we deallocate
	 the object at the right time.  */
      if (VAR_P (decl)
	  && DECL_SIZE (decl)
	  && !TREE_CONSTANT (DECL_SIZE (decl))
	  && STATEMENT_LIST_HAS_LABEL (cur_stmt_list))
	{
	  tree bind;
	  bind = build3 (BIND_EXPR, void_type_node, NULL, NULL, NULL);
	  TREE_SIDE_EFFECTS (bind) = 1;
	  add_stmt (bind);
	  BIND_EXPR_BODY (bind) = push_stmt_list ();
	}
      add_decl_expr (decl);
    }

  /* Let the middle end know about variables and functions -- but not
     static data members in uninstantiated class templates.  */
  if (VAR_OR_FUNCTION_DECL_P (decl))
    {
      if (VAR_P (decl))
	{
	  layout_var_decl (decl);
	  if (!flag_weak)
	    /* Check again now that we have an initializer.  */
	    maybe_commonize_var (decl);
	  /* A class-scope constexpr variable with an out-of-class declaration.
	     C++17 makes them implicitly inline, but still force it out.  */
	  if (DECL_INLINE_VAR_P (decl)
	      && !DECL_VAR_DECLARED_INLINE_P (decl)
	      && !DECL_TEMPLATE_INSTANTIATION (decl)
	      && !in_class_decl)
	    mark_needed (decl);
	}

      if (var_definition_p
	  /* With -fmerge-all-constants, gimplify_init_constructor
	     might add TREE_STATIC to aggregate variables.  */
	  && (TREE_STATIC (decl)
	      || (flag_merge_constants >= 2
		  && AGGREGATE_TYPE_P (type))))
	{
	  /* If a TREE_READONLY variable needs initialization
	     at runtime, it is no longer readonly and we need to
	     avoid MEM_READONLY_P being set on RTL created for it.  */
	  if (init)
	    {
	      if (TREE_READONLY (decl))
		TREE_READONLY (decl) = 0;
	      was_readonly = 0;
	    }
	  else if (was_readonly)
	    TREE_READONLY (decl) = 1;

	  /* Likewise if it needs destruction.  */
	  if (!decl_maybe_constant_destruction (decl, type))
	    TREE_READONLY (decl) = 0;
	}
      else if (VAR_P (decl)
	       && CP_DECL_THREAD_LOCAL_P (decl)
	       && (!DECL_EXTERNAL (decl) || flag_extern_tls_init)
	       && (was_readonly || TREE_READONLY (decl))
	       && var_needs_tls_wrapper (decl))
	{
	  /* TLS variables need dynamic initialization by the TLS wrapper
	     function, we don't want to hoist accesses to it before the
	     wrapper.  */
	  was_readonly = 0;
	  TREE_READONLY (decl) = 0;
	}

      make_rtl_for_nonlocal_decl (decl, init, asmspec);

      /* Check for abstractness of the type.  */
      if (var_definition_p)
	abstract_virtuals_error (decl, type);

      if (TREE_TYPE (decl) == error_mark_node)
	/* No initialization required.  */
	;
      else if (TREE_CODE (decl) == FUNCTION_DECL)
	{
	  if (init)
	    {
	      if (init == ridpointers[(int)RID_DEFAULT])
		{
		  /* An out-of-class default definition is defined at
		     the point where it is explicitly defaulted.  */
		  if (DECL_DELETED_FN (decl))
		    maybe_explain_implicit_delete (decl);
		  else if (DECL_INITIAL (decl) == error_mark_node)
		    synthesize_method (decl);
		}
	      else
		error_at (cp_expr_loc_or_loc (init,
					      DECL_SOURCE_LOCATION (decl)),
			  "function %q#D is initialized like a variable",
			  decl);
	    }
	  /* else no initialization required.  */
	}
      else if (DECL_EXTERNAL (decl)
	       && ! (DECL_LANG_SPECIFIC (decl)
		     && DECL_NOT_REALLY_EXTERN (decl)))
	{
	  /* check_initializer will have done any constant initialization.  */
	}
      /* A variable definition.  */
      else if (DECL_FUNCTION_SCOPE_P (decl) && !TREE_STATIC (decl))
	/* Initialize the local variable.  */
	initialize_local_var (decl, init);

      /* If a variable is defined, and then a subsequent
	 definition with external linkage is encountered, we will
	 get here twice for the same variable.  We want to avoid
	 calling expand_static_init more than once.  For variables
	 that are not static data members, we can call
	 expand_static_init only when we actually process the
	 initializer.  It is not legal to redeclare a static data
	 member, so this issue does not arise in that case.  */
      else if (var_definition_p && TREE_STATIC (decl))
	expand_static_init (decl, init);
    }

  /* If a CLEANUP_STMT was created to destroy a temporary bound to a
     reference, insert it in the statement-tree now.  */
  if (cleanups)
    {
      for (tree t : *cleanups)
	{
	  push_cleanup (NULL_TREE, t, false);
	  /* As in initialize_local_var.  */
	  wrap_temporary_cleanups (init, t);
	}
      release_tree_vector (cleanups);
    }

  if (was_readonly)
    TREE_READONLY (decl) = 1;

  if (flag_openmp
      && VAR_P (decl)
      && lookup_attribute ("omp declare target implicit",
			   DECL_ATTRIBUTES (decl)))
    {
      DECL_ATTRIBUTES (decl)
	= remove_attribute ("omp declare target implicit",
			    DECL_ATTRIBUTES (decl));
      complete_type (TREE_TYPE (decl));
      if (!cp_omp_mappable_type (TREE_TYPE (decl)))
	{
	  error ("%q+D in declare target directive does not have mappable"
		 " type", decl);
	  cp_omp_emit_unmappable_type_notes (TREE_TYPE (decl));
	}
      else if (!lookup_attribute ("omp declare target",
				  DECL_ATTRIBUTES (decl))
	       && !lookup_attribute ("omp declare target link",
				     DECL_ATTRIBUTES (decl)))
	{
	  DECL_ATTRIBUTES (decl)
	    = tree_cons (get_identifier ("omp declare target"),
			 NULL_TREE, DECL_ATTRIBUTES (decl));
	  symtab_node *node = symtab_node::get (decl);
	  if (node != NULL)
	    {
	      node->offloadable = 1;
	      if (ENABLE_OFFLOADING)
		{
		  g->have_offload = true;
		  if (is_a <varpool_node *> (node))
		    vec_safe_push (offload_vars, decl);
		}
	    }
	}
    }

  /* This is the last point we can lower alignment so give the target the
     chance to do so.  */
  if (VAR_P (decl)
      && !is_global_var (decl)
      && !DECL_HARD_REGISTER (decl))
    targetm.lower_local_decl_alignment (decl);

  invoke_plugin_callbacks (PLUGIN_FINISH_DECL, decl);
}

/* For class TYPE return itself or some its bases that contain
   any direct non-static data members.  Return error_mark_node if an
   error has been diagnosed.  */

static tree
find_decomp_class_base (location_t loc, tree type, tree ret)
{
  bool member_seen = false;
  for (tree field = TYPE_FIELDS (type); field; field = DECL_CHAIN (field))
    if (TREE_CODE (field) != FIELD_DECL
	|| DECL_ARTIFICIAL (field)
	|| DECL_UNNAMED_BIT_FIELD (field))
      continue;
    else if (ret)
      return type;
    else if (ANON_AGGR_TYPE_P (TREE_TYPE (field)))
      {
	if (TREE_CODE (TREE_TYPE (field)) == RECORD_TYPE)
	  error_at (loc, "cannot decompose class type %qT because it has an "
			 "anonymous struct member", type);
	else
	  error_at (loc, "cannot decompose class type %qT because it has an "
			 "anonymous union member", type);
	inform (DECL_SOURCE_LOCATION (field), "declared here");
	return error_mark_node;
      }
    else if (!accessible_p (type, field, true))
      {
	error_at (loc, "cannot decompose inaccessible member %qD of %qT",
		  field, type);
	inform (DECL_SOURCE_LOCATION (field),
		TREE_PRIVATE (field)
		? G_("declared private here")
		: G_("declared protected here"));
	return error_mark_node;
      }
    else
      member_seen = true;

  tree base_binfo, binfo;
  tree orig_ret = ret;
  int i;
  if (member_seen)
    ret = type;
  for (binfo = TYPE_BINFO (type), i = 0;
       BINFO_BASE_ITERATE (binfo, i, base_binfo); i++)
    {
      tree t = find_decomp_class_base (loc, TREE_TYPE (base_binfo), ret);
      if (t == error_mark_node)
	return error_mark_node;
      if (t != NULL_TREE && t != ret)
	{
	  if (ret == type)
	    {
	      error_at (loc, "cannot decompose class type %qT: both it and "
			     "its base class %qT have non-static data members",
			type, t);
	      return error_mark_node;
	    }
	  else if (orig_ret != NULL_TREE)
	    return t;
	  else if (ret != NULL_TREE)
	    {
	      error_at (loc, "cannot decompose class type %qT: its base "
			     "classes %qT and %qT have non-static data "
			     "members", type, ret, t);
	      return error_mark_node;
	    }
	  else
	    ret = t;
	}
    }
  return ret;
}

/* Return std::tuple_size<TYPE>::value.  */

static tree
get_tuple_size (tree type)
{
  tree args = make_tree_vec (1);
  TREE_VEC_ELT (args, 0) = type;
  tree inst = lookup_template_class (tuple_size_identifier, args,
				     /*in_decl*/NULL_TREE,
				     /*context*/std_node,
				     /*entering_scope*/false, tf_none);
  inst = complete_type (inst);
  if (inst == error_mark_node || !COMPLETE_TYPE_P (inst))
    return NULL_TREE;
  tree val = lookup_qualified_name (inst, value_identifier,
				    LOOK_want::NORMAL, /*complain*/false);
  if (TREE_CODE (val) == VAR_DECL || TREE_CODE (val) == CONST_DECL)
    val = maybe_constant_value (val);
  if (TREE_CODE (val) == INTEGER_CST)
    return val;
  else
    return error_mark_node;
}

/* Return std::tuple_element<I,TYPE>::type.  */

static tree
get_tuple_element_type (tree type, unsigned i)
{
  tree args = make_tree_vec (2);
  TREE_VEC_ELT (args, 0) = build_int_cst (integer_type_node, i);
  TREE_VEC_ELT (args, 1) = type;
  tree inst = lookup_template_class (tuple_element_identifier, args,
				     /*in_decl*/NULL_TREE,
				     /*context*/std_node,
				     /*entering_scope*/false,
				     tf_warning_or_error);
  return make_typename_type (inst, type_identifier,
			     none_type, tf_warning_or_error);
}

/* Return e.get<i>() or get<i>(e).  */

static tree
get_tuple_decomp_init (tree decl, unsigned i)
{
  tree targs = make_tree_vec (1);
  TREE_VEC_ELT (targs, 0) = build_int_cst (integer_type_node, i);

  tree etype = TREE_TYPE (decl);
  tree e = convert_from_reference (decl);

  /* [The id-expression] e is an lvalue if the type of the entity e is an
     lvalue reference and an xvalue otherwise.  */
  if (!TYPE_REF_P (etype)
      || TYPE_REF_IS_RVALUE (etype))
    e = move (e);

  tree fns = lookup_qualified_name (TREE_TYPE (e), get__identifier,
				    LOOK_want::NORMAL, /*complain*/false);
  bool use_member_get = false;

  /* To use a member get, member lookup must find at least one
     declaration that is a function template
     whose first template parameter is a non-type parameter.  */
  for (lkp_iterator iter (MAYBE_BASELINK_FUNCTIONS (fns)); iter; ++iter)
    {
      tree fn = *iter;
      if (TREE_CODE (fn) == TEMPLATE_DECL)
	{
	  tree tparms = DECL_TEMPLATE_PARMS (fn);
	  tree parm = TREE_VEC_ELT (INNERMOST_TEMPLATE_PARMS (tparms), 0);
	  if (TREE_CODE (TREE_VALUE (parm)) == PARM_DECL)
	    {
	      use_member_get = true;
	      break;
	    }
	}
    }

  if (use_member_get)
    {
      fns = lookup_template_function (fns, targs);
      return build_new_method_call (e, fns, /*args*/NULL,
				    /*path*/NULL_TREE, LOOKUP_NORMAL,
				    /*fn_p*/NULL, tf_warning_or_error);
    }
  else
    {
      releasing_vec args (make_tree_vector_single (e));
      fns = lookup_template_function (get__identifier, targs);
      fns = perform_koenig_lookup (fns, args, tf_warning_or_error);
      return finish_call_expr (fns, &args, /*novirt*/false,
			       /*koenig*/true, tf_warning_or_error);
    }
}

/* It's impossible to recover the decltype of a tuple decomposition variable
   based on the actual type of the variable, so store it in a hash table.  */

static GTY((cache)) decl_tree_cache_map *decomp_type_table;

tree
lookup_decomp_type (tree v)
{
  return *decomp_type_table->get (v);
}

/* Mangle a decomposition declaration if needed.  Arguments like
   in cp_finish_decomp.  */

void
cp_maybe_mangle_decomp (tree decl, tree first, unsigned int count)
{
  if (!processing_template_decl
      && !error_operand_p (decl)
      && TREE_STATIC (decl))
    {
      auto_vec<tree, 16> v;
      v.safe_grow (count, true);
      tree d = first;
      for (unsigned int i = 0; i < count; i++, d = DECL_CHAIN (d))
	v[count - i - 1] = d;
      SET_DECL_ASSEMBLER_NAME (decl, mangle_decomp (decl, v));
      maybe_apply_pragma_weak (decl);
    }
}

/* Finish a decomposition declaration.  DECL is the underlying declaration
   "e", FIRST is the head of a chain of decls for the individual identifiers
   chained through DECL_CHAIN in reverse order and COUNT is the number of
   those decls.  */

void
cp_finish_decomp (tree decl, tree first, unsigned int count)
{
  if (error_operand_p (decl))
    {
     error_out:
      while (count--)
	{
	  TREE_TYPE (first) = error_mark_node;
	  if (DECL_HAS_VALUE_EXPR_P (first))
	    {
	      SET_DECL_VALUE_EXPR (first, NULL_TREE);
	      DECL_HAS_VALUE_EXPR_P (first) = 0;
	    }
	  first = DECL_CHAIN (first);
	}
      if (DECL_P (decl) && DECL_NAMESPACE_SCOPE_P (decl))
	SET_DECL_ASSEMBLER_NAME (decl, get_identifier ("<decomp>"));
      return;
    }

  location_t loc = DECL_SOURCE_LOCATION (decl);
  if (type_dependent_expression_p (decl)
      /* This happens for range for when not in templates.
	 Still add the DECL_VALUE_EXPRs for later processing.  */
      || (!processing_template_decl
	  && type_uses_auto (TREE_TYPE (decl))))
    {
      for (unsigned int i = 0; i < count; i++)
	{
	  if (!DECL_HAS_VALUE_EXPR_P (first))
	    {
	      tree v = build_nt (ARRAY_REF, decl,
				 size_int (count - i - 1),
				 NULL_TREE, NULL_TREE);
	      SET_DECL_VALUE_EXPR (first, v);
	      DECL_HAS_VALUE_EXPR_P (first) = 1;
	    }
	  if (processing_template_decl)
	    fit_decomposition_lang_decl (first, decl);
	  first = DECL_CHAIN (first);
	}
      return;
    }

  auto_vec<tree, 16> v;
  v.safe_grow (count, true);
  tree d = first;
  for (unsigned int i = 0; i < count; i++, d = DECL_CHAIN (d))
    {
      v[count - i - 1] = d;
      fit_decomposition_lang_decl (d, decl);
    }

  tree type = TREE_TYPE (decl);
  tree dexp = decl;

  if (TYPE_REF_P (type))
    {
      dexp = convert_from_reference (dexp);
      type = complete_type (TREE_TYPE (type));
      if (type == error_mark_node)
	goto error_out;
      if (!COMPLETE_TYPE_P (type))
	{
	  error_at (loc, "structured binding refers to incomplete type %qT",
		    type);
	  goto error_out;
	}
    }

  tree eltype = NULL_TREE;
  unsigned HOST_WIDE_INT eltscnt = 0;
  if (TREE_CODE (type) == ARRAY_TYPE)
    {
      tree nelts;
      nelts = array_type_nelts_top (type);
      if (nelts == error_mark_node)
	goto error_out;
      if (!tree_fits_uhwi_p (nelts))
	{
	  error_at (loc, "cannot decompose variable length array %qT", type);
	  goto error_out;
	}
      eltscnt = tree_to_uhwi (nelts);
      if (count != eltscnt)
	{
       cnt_mismatch:
	  if (count > eltscnt)
	    error_n (loc, count,
		     "%u name provided for structured binding",
		     "%u names provided for structured binding", count);
	  else
	    error_n (loc, count,
		     "only %u name provided for structured binding",
		     "only %u names provided for structured binding", count);
	  inform_n (loc, eltscnt,
		    "while %qT decomposes into %wu element",
		    "while %qT decomposes into %wu elements",
		    type, eltscnt);
	  goto error_out;
	}
      eltype = TREE_TYPE (type);
      for (unsigned int i = 0; i < count; i++)
	{
	  TREE_TYPE (v[i]) = eltype;
	  layout_decl (v[i], 0);
	  if (processing_template_decl)
	    continue;
	  tree t = unshare_expr (dexp);
	  t = build4_loc (DECL_SOURCE_LOCATION (v[i]), ARRAY_REF,
			  eltype, t, size_int (i), NULL_TREE,
			  NULL_TREE);
	  SET_DECL_VALUE_EXPR (v[i], t);
	  DECL_HAS_VALUE_EXPR_P (v[i]) = 1;
	}
    }
  /* 2 GNU extensions.  */
  else if (TREE_CODE (type) == COMPLEX_TYPE)
    {
      eltscnt = 2;
      if (count != eltscnt)
	goto cnt_mismatch;
      eltype = cp_build_qualified_type (TREE_TYPE (type), TYPE_QUALS (type));
      for (unsigned int i = 0; i < count; i++)
	{
	  TREE_TYPE (v[i]) = eltype;
	  layout_decl (v[i], 0);
	  if (processing_template_decl)
	    continue;
	  tree t = unshare_expr (dexp);
	  t = build1_loc (DECL_SOURCE_LOCATION (v[i]),
			  i ? IMAGPART_EXPR : REALPART_EXPR, eltype,
			  t);
	  SET_DECL_VALUE_EXPR (v[i], t);
	  DECL_HAS_VALUE_EXPR_P (v[i]) = 1;
	}
    }
  else if (TREE_CODE (type) == VECTOR_TYPE)
    {
      if (!TYPE_VECTOR_SUBPARTS (type).is_constant (&eltscnt))
	{
	  error_at (loc, "cannot decompose variable length vector %qT", type);
	  goto error_out;
	}
      if (count != eltscnt)
	goto cnt_mismatch;
      eltype = cp_build_qualified_type (TREE_TYPE (type), TYPE_QUALS (type));
      for (unsigned int i = 0; i < count; i++)
	{
	  TREE_TYPE (v[i]) = eltype;
	  layout_decl (v[i], 0);
	  if (processing_template_decl)
	    continue;
	  tree t = unshare_expr (dexp);
	  convert_vector_to_array_for_subscript (DECL_SOURCE_LOCATION (v[i]),
						 &t, size_int (i));
	  t = build4_loc (DECL_SOURCE_LOCATION (v[i]), ARRAY_REF,
			  eltype, t, size_int (i), NULL_TREE,
			  NULL_TREE);
	  SET_DECL_VALUE_EXPR (v[i], t);
	  DECL_HAS_VALUE_EXPR_P (v[i]) = 1;
	}
    }
  else if (tree tsize = get_tuple_size (type))
    {
      if (tsize == error_mark_node)
	{
	  error_at (loc, "%<std::tuple_size<%T>::value%> is not an integral "
			 "constant expression", type);
	  goto error_out;
	}
      if (!tree_fits_uhwi_p (tsize))
	{
	  error_n (loc, count,
		   "%u name provided for structured binding",
		   "%u names provided for structured binding", count);
	  inform (loc, "while %qT decomposes into %E elements",
		  type, tsize);
	  goto error_out;
	}
      eltscnt = tree_to_uhwi (tsize);
      if (count != eltscnt)
	goto cnt_mismatch;
      int save_read = DECL_READ_P (decl);	
      for (unsigned i = 0; i < count; ++i)
	{
	  location_t sloc = input_location;
	  location_t dloc = DECL_SOURCE_LOCATION (v[i]);

	  input_location = dloc;
	  tree init = get_tuple_decomp_init (decl, i);
	  tree eltype = (init == error_mark_node ? error_mark_node
			 : get_tuple_element_type (type, i));
	  input_location = sloc;

	  if (VOID_TYPE_P (eltype))
	    {
	      error ("%<std::tuple_element<%u, %T>::type%> is %<void%>",
		     i, type);
	      eltype = error_mark_node;
	    }
	  if (init == error_mark_node || eltype == error_mark_node)
	    {
	      inform (dloc, "in initialization of structured binding "
		      "variable %qD", v[i]);
	      goto error_out;
	    }
	  /* Save the decltype away before reference collapse.  */
	  hash_map_safe_put<hm_ggc> (decomp_type_table, v[i], eltype);
	  eltype = cp_build_reference_type (eltype, !lvalue_p (init));
	  TREE_TYPE (v[i]) = eltype;
	  layout_decl (v[i], 0);
	  if (DECL_HAS_VALUE_EXPR_P (v[i]))
	    {
	      /* In this case the names are variables, not just proxies.  */
	      SET_DECL_VALUE_EXPR (v[i], NULL_TREE);
	      DECL_HAS_VALUE_EXPR_P (v[i]) = 0;
	    }
	  if (!processing_template_decl)
	    {
	      copy_linkage (v[i], decl);
	      cp_finish_decl (v[i], init, /*constexpr*/false,
			      /*asm*/NULL_TREE, LOOKUP_NORMAL);
	    }
	}
      /* Ignore reads from the underlying decl performed during initialization
	 of the individual variables.  If those will be read, we'll mark
	 the underlying decl as read at that point.  */
      DECL_READ_P (decl) = save_read;
    }
  else if (TREE_CODE (type) == UNION_TYPE)
    {
      error_at (loc, "cannot decompose union type %qT", type);
      goto error_out;
    }
  else if (!CLASS_TYPE_P (type))
    {
      error_at (loc, "cannot decompose non-array non-class type %qT", type);
      goto error_out;
    }
  else if (LAMBDA_TYPE_P (type))
    {
      error_at (loc, "cannot decompose lambda closure type %qT", type);
      goto error_out;
    }
  else if (processing_template_decl && complete_type (type) == error_mark_node)
    goto error_out;
  else if (processing_template_decl && !COMPLETE_TYPE_P (type))
    pedwarn (loc, 0, "structured binding refers to incomplete class type %qT",
	     type);
  else
    {
      tree btype = find_decomp_class_base (loc, type, NULL_TREE);
      if (btype == error_mark_node)
	goto error_out;
      else if (btype == NULL_TREE)
	{
	  error_at (loc, "cannot decompose class type %qT without non-static "
			 "data members", type);
	  goto error_out;
	}
      for (tree field = TYPE_FIELDS (btype); field; field = TREE_CHAIN (field))
	if (TREE_CODE (field) != FIELD_DECL
	    || DECL_ARTIFICIAL (field)
	    || DECL_UNNAMED_BIT_FIELD (field))
	  continue;
	else
	  eltscnt++;
      if (count != eltscnt)
	goto cnt_mismatch;
      tree t = dexp;
      if (type != btype)
	{
	  t = convert_to_base (t, btype, /*check_access*/true,
			       /*nonnull*/false, tf_warning_or_error);
	  type = btype;
	}
      unsigned int i = 0;
      for (tree field = TYPE_FIELDS (btype); field; field = TREE_CHAIN (field))
	if (TREE_CODE (field) != FIELD_DECL
	    || DECL_ARTIFICIAL (field)
	    || DECL_UNNAMED_BIT_FIELD (field))
	  continue;
	else
	  {
	    tree tt = finish_non_static_data_member (field, unshare_expr (t),
						     NULL_TREE);
	    if (REFERENCE_REF_P (tt))
	      tt = TREE_OPERAND (tt, 0);
	    TREE_TYPE (v[i]) = TREE_TYPE (tt);
	    layout_decl (v[i], 0);
	    if (!processing_template_decl)
	      {
		SET_DECL_VALUE_EXPR (v[i], tt);
		DECL_HAS_VALUE_EXPR_P (v[i]) = 1;
	      }
	    i++;
	  }
    }
  if (processing_template_decl)
    {
      for (unsigned int i = 0; i < count; i++)
	if (!DECL_HAS_VALUE_EXPR_P (v[i]))
	  {
	    tree a = build_nt (ARRAY_REF, decl, size_int (i),
			       NULL_TREE, NULL_TREE);
	    SET_DECL_VALUE_EXPR (v[i], a);
	    DECL_HAS_VALUE_EXPR_P (v[i]) = 1;
	  }
    }
}

/* Returns a declaration for a VAR_DECL as if:

     extern "C" TYPE NAME;

   had been seen.  Used to create compiler-generated global
   variables.  */

static tree
declare_global_var (tree name, tree type)
{
  auto cookie = push_abi_namespace (global_namespace);
  tree decl = build_decl (input_location, VAR_DECL, name, type);
  TREE_PUBLIC (decl) = 1;
  DECL_EXTERNAL (decl) = 1;
  DECL_ARTIFICIAL (decl) = 1;
  DECL_CONTEXT (decl) = FROB_CONTEXT (current_namespace);
  /* If the user has explicitly declared this variable (perhaps
     because the code we are compiling is part of a low-level runtime
     library), then it is possible that our declaration will be merged
     with theirs by pushdecl.  */
  decl = pushdecl (decl);
  cp_finish_decl (decl, NULL_TREE, false, NULL_TREE, 0);
  pop_abi_namespace (cookie, global_namespace);

  return decl;
}

/* Returns the type for the argument to "__cxa_atexit" (or "atexit",
   if "__cxa_atexit" is not being used) corresponding to the function
   to be called when the program exits.  */

static tree
get_atexit_fn_ptr_type (void)
{
  tree fn_type;

  if (!atexit_fn_ptr_type_node)
    {
      tree arg_type;
      if (flag_use_cxa_atexit 
	  && !targetm.cxx.use_atexit_for_cxa_atexit ())
	/* The parameter to "__cxa_atexit" is "void (*)(void *)".  */
	arg_type = ptr_type_node;
      else
	/* The parameter to "atexit" is "void (*)(void)".  */
	arg_type = NULL_TREE;
      
      fn_type = build_function_type_list (void_type_node,
					  arg_type, NULL_TREE);
      atexit_fn_ptr_type_node = build_pointer_type (fn_type);
    }

  return atexit_fn_ptr_type_node;
}

/* Returns a pointer to the `atexit' function.  Note that if
   FLAG_USE_CXA_ATEXIT is nonzero, then this will actually be the new
   `__cxa_atexit' function specified in the IA64 C++ ABI.  */

static tree
get_atexit_node (void)
{
  tree atexit_fndecl;
  tree fn_type;
  tree fn_ptr_type;
  const char *name;
  bool use_aeabi_atexit;
  tree ctx = global_namespace;

  if (atexit_node)
    return atexit_node;

  if (flag_use_cxa_atexit && !targetm.cxx.use_atexit_for_cxa_atexit ())
    {
      /* The declaration for `__cxa_atexit' is:

	   int __cxa_atexit (void (*)(void *), void *, void *)

	 We build up the argument types and then the function type
	 itself.  */
      tree argtype0, argtype1, argtype2;

      use_aeabi_atexit = targetm.cxx.use_aeabi_atexit ();
      /* First, build the pointer-to-function type for the first
	 argument.  */
      fn_ptr_type = get_atexit_fn_ptr_type ();
      /* Then, build the rest of the argument types.  */
      argtype2 = ptr_type_node;
      if (use_aeabi_atexit)
	{
	  argtype1 = fn_ptr_type;
	  argtype0 = ptr_type_node;
	}
      else
	{
	  argtype1 = ptr_type_node;
	  argtype0 = fn_ptr_type;
	}
      /* And the final __cxa_atexit type.  */
      fn_type = build_function_type_list (integer_type_node,
					  argtype0, argtype1, argtype2,
					  NULL_TREE);
      /* ... which needs noexcept.  */
      fn_type = build_exception_variant (fn_type, noexcept_true_spec);
      if (use_aeabi_atexit)
	{
	  name = "__aeabi_atexit";
	  push_to_top_level ();
	  int n = push_namespace (get_identifier ("__aeabiv1"), false);
	  ctx = current_namespace;
	  while (n--)
	    pop_namespace ();
	  pop_from_top_level ();
	}
      else
	{
	  name = "__cxa_atexit";
	  ctx = abi_node;
	}
    }
  else
    {
      /* The declaration for `atexit' is:

	   int atexit (void (*)());

	 We build up the argument types and then the function type
	 itself.  */
      fn_ptr_type = get_atexit_fn_ptr_type ();
      /* Build the final atexit type.  */
      fn_type = build_function_type_list (integer_type_node,
					  fn_ptr_type, NULL_TREE);
      /* ... which needs noexcept.  */
      fn_type = build_exception_variant (fn_type, noexcept_true_spec);
      name = "atexit";
    }

  /* Now, build the function declaration.  */
  push_lang_context (lang_name_c);
  auto cookie = push_abi_namespace (ctx);
  atexit_fndecl = build_library_fn_ptr (name, fn_type, ECF_LEAF | ECF_NOTHROW);
  DECL_CONTEXT (atexit_fndecl) = FROB_CONTEXT (current_namespace);
  /* Install as hidden builtin so we're (a) more relaxed about
    exception spec matching and (b) will not give a confusing location
    in diagnostic and (c) won't magically appear in user-visible name
    lookups.  */
  DECL_SOURCE_LOCATION (atexit_fndecl) = BUILTINS_LOCATION;
  atexit_fndecl = pushdecl (atexit_fndecl, /*hiding=*/true);
  pop_abi_namespace (cookie, ctx);
  mark_used (atexit_fndecl);
  pop_lang_context ();
  atexit_node = decay_conversion (atexit_fndecl, tf_warning_or_error);

  return atexit_node;
}

/* Like get_atexit_node, but for thread-local cleanups.  */

static tree
get_thread_atexit_node (void)
{
  /* The declaration for `__cxa_thread_atexit' is:

     int __cxa_thread_atexit (void (*)(void *), void *, void *) */
  tree fn_type = build_function_type_list (integer_type_node,
					   get_atexit_fn_ptr_type (),
					   ptr_type_node, ptr_type_node,
					   NULL_TREE);

  /* Now, build the function declaration.  */
  tree atexit_fndecl = build_library_fn_ptr ("__cxa_thread_atexit", fn_type,
					     ECF_LEAF | ECF_NOTHROW);
  return decay_conversion (atexit_fndecl, tf_warning_or_error);
}

/* Returns the __dso_handle VAR_DECL.  */

static tree
get_dso_handle_node (void)
{
  if (dso_handle_node)
    return dso_handle_node;

  /* Declare the variable.  */
  dso_handle_node = declare_global_var (get_identifier ("__dso_handle"),
					ptr_type_node);

#ifdef HAVE_GAS_HIDDEN
  if (dso_handle_node != error_mark_node)
    {
      DECL_VISIBILITY (dso_handle_node) = VISIBILITY_HIDDEN;
      DECL_VISIBILITY_SPECIFIED (dso_handle_node) = 1;
    }
#endif

  return dso_handle_node;
}

/* Begin a new function with internal linkage whose job will be simply
   to destroy some particular variable.  */

static GTY(()) int start_cleanup_cnt;

static tree
start_cleanup_fn (void)
{
  char name[32];

  push_to_top_level ();

  /* No need to mangle this.  */
  push_lang_context (lang_name_c);

  /* Build the name of the function.  */
  sprintf (name, "__tcf_%d", start_cleanup_cnt++);
  /* Build the function declaration.  */
  tree fntype = TREE_TYPE (get_atexit_fn_ptr_type ());
  tree fndecl = build_lang_decl (FUNCTION_DECL, get_identifier (name), fntype);
  DECL_CONTEXT (fndecl) = FROB_CONTEXT (current_namespace);
  /* It's a function with internal linkage, generated by the
     compiler.  */
  TREE_PUBLIC (fndecl) = 0;
  DECL_ARTIFICIAL (fndecl) = 1;
  /* Make the function `inline' so that it is only emitted if it is
     actually needed.  It is unlikely that it will be inlined, since
     it is only called via a function pointer, but we avoid unnecessary
     emissions this way.  */
  DECL_DECLARED_INLINE_P (fndecl) = 1;
  DECL_INTERFACE_KNOWN (fndecl) = 1;
  if (flag_use_cxa_atexit && !targetm.cxx.use_atexit_for_cxa_atexit ())
    {
      /* Build the parameter.  */
      tree parmdecl = cp_build_parm_decl (fndecl, NULL_TREE, ptr_type_node);
      TREE_USED (parmdecl) = 1;
      DECL_READ_P (parmdecl) = 1;
      DECL_ARGUMENTS (fndecl) = parmdecl;
    }

  fndecl = pushdecl (fndecl, /*hidden=*/true);
  start_preparsed_function (fndecl, NULL_TREE, SF_PRE_PARSED);

  pop_lang_context ();

  return current_function_decl;
}

/* Finish the cleanup function begun by start_cleanup_fn.  */

static void
end_cleanup_fn (void)
{
  expand_or_defer_fn (finish_function (/*inline_p=*/false));

  pop_from_top_level ();
}

/* Generate code to handle the destruction of DECL, an object with
   static storage duration.  */

tree
register_dtor_fn (tree decl)
{
  tree cleanup;
  tree addr;
  tree compound_stmt;
  tree fcall;
  tree type;
  bool ob_parm, dso_parm, use_dtor;
  tree arg0, arg1, arg2;
  tree atex_node;

  type = TREE_TYPE (decl);
  if (TYPE_HAS_TRIVIAL_DESTRUCTOR (type))
    return void_node;

  if (decl_maybe_constant_destruction (decl, type)
      && DECL_INITIALIZED_BY_CONSTANT_EXPRESSION_P (decl))
    {
      cxx_maybe_build_cleanup (decl, tf_warning_or_error);
      return void_node;
    }

  /* If we're using "__cxa_atexit" (or "__cxa_thread_atexit" or
     "__aeabi_atexit"), and DECL is a class object, we can just pass the
     destructor to "__cxa_atexit"; we don't have to build a temporary
     function to do the cleanup.  */
  dso_parm = (flag_use_cxa_atexit
	      && !targetm.cxx.use_atexit_for_cxa_atexit ());
  ob_parm = (CP_DECL_THREAD_LOCAL_P (decl) || dso_parm);
  use_dtor = ob_parm && CLASS_TYPE_P (type);
  if (use_dtor)
    {
      cleanup = get_class_binding (type, complete_dtor_identifier);

      /* Make sure it is accessible.  */
      perform_or_defer_access_check (TYPE_BINFO (type), cleanup, cleanup,
				     tf_warning_or_error);
    }
  else
    {
      /* Call build_cleanup before we enter the anonymous function so
	 that any access checks will be done relative to the current
	 scope, rather than the scope of the anonymous function.  */
      build_cleanup (decl);
  
      /* Now start the function.  */
      cleanup = start_cleanup_fn ();
      
      /* Now, recompute the cleanup.  It may contain SAVE_EXPRs that refer
	 to the original function, rather than the anonymous one.  That
	 will make the back end think that nested functions are in use,
	 which causes confusion.  */
      push_deferring_access_checks (dk_no_check);
      fcall = build_cleanup (decl);
      pop_deferring_access_checks ();
      
      /* Create the body of the anonymous function.  */
      compound_stmt = begin_compound_stmt (BCS_FN_BODY);
      finish_expr_stmt (fcall);
      finish_compound_stmt (compound_stmt);
      end_cleanup_fn ();
    }

  /* Call atexit with the cleanup function.  */
  mark_used (cleanup);
  cleanup = build_address (cleanup);

  if (CP_DECL_THREAD_LOCAL_P (decl))
    atex_node = get_thread_atexit_node ();
  else
    atex_node = get_atexit_node ();

  if (use_dtor)
    {
      /* We must convert CLEANUP to the type that "__cxa_atexit"
	 expects.  */
      cleanup = build_nop (get_atexit_fn_ptr_type (), cleanup);
      /* "__cxa_atexit" will pass the address of DECL to the
	 cleanup function.  */
      mark_used (decl);
      addr = build_address (decl);
      /* The declared type of the parameter to "__cxa_atexit" is
	 "void *".  For plain "T*", we could just let the
	 machinery in cp_build_function_call convert it -- but if the
	 type is "cv-qualified T *", then we need to convert it
	 before passing it in, to avoid spurious errors.  */
      addr = build_nop (ptr_type_node, addr);
    }
  else
    /* Since the cleanup functions we build ignore the address
       they're given, there's no reason to pass the actual address
       in, and, in general, it's cheaper to pass NULL than any
       other value.  */
    addr = null_pointer_node;

  if (dso_parm)
    arg2 = cp_build_addr_expr (get_dso_handle_node (),
			       tf_warning_or_error);
  else if (ob_parm)
    /* Just pass NULL to the dso handle parm if we don't actually
       have a DSO handle on this target.  */
    arg2 = null_pointer_node;
  else
    arg2 = NULL_TREE;

  if (ob_parm)
    {
      if (!CP_DECL_THREAD_LOCAL_P (decl)
	  && targetm.cxx.use_aeabi_atexit ())
	{
	  arg1 = cleanup;
	  arg0 = addr;
	}
      else
	{
	  arg1 = addr;
	  arg0 = cleanup;
	}
    }
  else
    {
      arg0 = cleanup;
      arg1 = NULL_TREE;
    }
  return cp_build_function_call_nary (atex_node, tf_warning_or_error,
				      arg0, arg1, arg2, NULL_TREE);
}

/* DECL is a VAR_DECL with static storage duration.  INIT, if present,
   is its initializer.  Generate code to handle the construction
   and destruction of DECL.  */

static void
expand_static_init (tree decl, tree init)
{
  gcc_assert (VAR_P (decl));
  gcc_assert (TREE_STATIC (decl));

  /* Some variables require no dynamic initialization.  */
  if (decl_maybe_constant_destruction (decl, TREE_TYPE (decl)))
    {
      /* Make sure the destructor is callable.  */
      cxx_maybe_build_cleanup (decl, tf_warning_or_error);
      if (!init)
	return;
    }

  if (CP_DECL_THREAD_LOCAL_P (decl) && DECL_GNU_TLS_P (decl)
      && !DECL_FUNCTION_SCOPE_P (decl))
    {
      location_t dloc = DECL_SOURCE_LOCATION (decl);
      if (init)
	error_at (dloc, "non-local variable %qD declared %<__thread%> "
		  "needs dynamic initialization", decl);
      else
	error_at (dloc, "non-local variable %qD declared %<__thread%> "
		  "has a non-trivial destructor", decl);
      static bool informed;
      if (!informed)
	{
	  inform (dloc, "C++11 %<thread_local%> allows dynamic "
		  "initialization and destruction");
	  informed = true;
	}
      return;
    }

  if (DECL_FUNCTION_SCOPE_P (decl))
    {
      /* Emit code to perform this initialization but once.  */
      tree if_stmt = NULL_TREE, inner_if_stmt = NULL_TREE;
      tree then_clause = NULL_TREE, inner_then_clause = NULL_TREE;
      tree guard, guard_addr;
      tree flag, begin;
      /* We don't need thread-safety code for thread-local vars.  */
      bool thread_guard = (flag_threadsafe_statics
			   && !CP_DECL_THREAD_LOCAL_P (decl));

      /* Emit code to perform this initialization but once.  This code
	 looks like:

	   static <type> guard;
	   if (!__atomic_load (guard.first_byte)) {
	     if (__cxa_guard_acquire (&guard)) {
	       bool flag = false;
	       try {
		 // Do initialization.
		 flag = true; __cxa_guard_release (&guard);
		 // Register variable for destruction at end of program.
	       } catch {
		 if (!flag) __cxa_guard_abort (&guard);
	       }
	     }
	   }

	 Note that the `flag' variable is only set to 1 *after* the
	 initialization is complete.  This ensures that an exception,
	 thrown during the construction, will cause the variable to
	 reinitialized when we pass through this code again, as per:

	   [stmt.dcl]

	   If the initialization exits by throwing an exception, the
	   initialization is not complete, so it will be tried again
	   the next time control enters the declaration.

	 This process should be thread-safe, too; multiple threads
	 should not be able to initialize the variable more than
	 once.  */

      /* Create the guard variable.  */
      guard = get_guard (decl);

      /* Begin the conditional initialization.  */
      if_stmt = begin_if_stmt ();

      finish_if_stmt_cond (get_guard_cond (guard, thread_guard), if_stmt);
      then_clause = begin_compound_stmt (BCS_NO_SCOPE);

      if (thread_guard)
	{
	  tree vfntype = NULL_TREE;
	  tree acquire_name, release_name, abort_name;
	  tree acquire_fn, release_fn, abort_fn;
	  guard_addr = build_address (guard);

	  acquire_name = get_identifier ("__cxa_guard_acquire");
	  release_name = get_identifier ("__cxa_guard_release");
	  abort_name = get_identifier ("__cxa_guard_abort");
	  acquire_fn = get_global_binding (acquire_name);
	  release_fn = get_global_binding (release_name);
	  abort_fn = get_global_binding (abort_name);
	  if (!acquire_fn)
	    acquire_fn = push_library_fn
	      (acquire_name, build_function_type_list (integer_type_node,
						       TREE_TYPE (guard_addr),
						       NULL_TREE),
	       NULL_TREE, ECF_NOTHROW);
	  if (!release_fn || !abort_fn)
	    vfntype = build_function_type_list (void_type_node,
						TREE_TYPE (guard_addr),
						NULL_TREE);
	  if (!release_fn)
	    release_fn = push_library_fn (release_name, vfntype, NULL_TREE,
					  ECF_NOTHROW);
	  if (!abort_fn)
	    abort_fn = push_library_fn (abort_name, vfntype, NULL_TREE,
					ECF_NOTHROW | ECF_LEAF);

	  inner_if_stmt = begin_if_stmt ();
	  finish_if_stmt_cond (build_call_n (acquire_fn, 1, guard_addr),
			       inner_if_stmt);

	  inner_then_clause = begin_compound_stmt (BCS_NO_SCOPE);
	  begin = get_target_expr (boolean_false_node);
	  flag = TARGET_EXPR_SLOT (begin);

	  TARGET_EXPR_CLEANUP (begin)
	    = build3 (COND_EXPR, void_type_node, flag,
		      void_node,
		      build_call_n (abort_fn, 1, guard_addr));
	  CLEANUP_EH_ONLY (begin) = 1;

	  /* Do the initialization itself.  */
	  init = add_stmt_to_compound (begin, init);
	  init = add_stmt_to_compound (init,
				       build2 (MODIFY_EXPR, void_type_node,
					       flag, boolean_true_node));

	  /* Use atexit to register a function for destroying this static
	     variable.  Do this before calling __cxa_guard_release.  */
	  init = add_stmt_to_compound (init, register_dtor_fn (decl));

	  init = add_stmt_to_compound (init, build_call_n (release_fn, 1,
							   guard_addr));
	}
      else
	{
	  init = add_stmt_to_compound (init, set_guard (guard));

	  /* Use atexit to register a function for destroying this static
	     variable.  */
	  init = add_stmt_to_compound (init, register_dtor_fn (decl));
	}

      finish_expr_stmt (init);

      if (thread_guard)
	{
	  finish_compound_stmt (inner_then_clause);
	  finish_then_clause (inner_if_stmt);
	  finish_if_stmt (inner_if_stmt);
	}

      finish_compound_stmt (then_clause);
      finish_then_clause (if_stmt);
      finish_if_stmt (if_stmt);
    }
  else if (CP_DECL_THREAD_LOCAL_P (decl))
    tls_aggregates = tree_cons (init, decl, tls_aggregates);
  else
    static_aggregates = tree_cons (init, decl, static_aggregates);
}


/* Make TYPE a complete type based on INITIAL_VALUE.
   Return 0 if successful, 1 if INITIAL_VALUE can't be deciphered,
   2 if there was no information (in which case assume 0 if DO_DEFAULT),
   3 if the initializer list is empty (in pedantic mode). */

int
cp_complete_array_type (tree *ptype, tree initial_value, bool do_default)
{
  int failure;
  tree type, elt_type;

  /* Don't get confused by a CONSTRUCTOR for some other type.  */
  if (initial_value && TREE_CODE (initial_value) == CONSTRUCTOR
      && !BRACE_ENCLOSED_INITIALIZER_P (initial_value)
      && TREE_CODE (TREE_TYPE (initial_value)) != ARRAY_TYPE)
    return 1;

  if (initial_value)
    {
      /* An array of character type can be initialized from a
	 brace-enclosed string constant so call reshape_init to
	 remove the optional braces from a braced string literal.  */
      if (char_type_p (TYPE_MAIN_VARIANT (TREE_TYPE (*ptype)))
	  && BRACE_ENCLOSED_INITIALIZER_P (initial_value))
	initial_value = reshape_init (*ptype, initial_value,
				      tf_warning_or_error);

      /* If any of the elements are parameter packs, we can't actually
	 complete this type now because the array size is dependent.  */
      if (TREE_CODE (initial_value) == CONSTRUCTOR)
	for (auto &e: CONSTRUCTOR_ELTS (initial_value))
	  if (PACK_EXPANSION_P (e.value))
	    return 0;
    }

  failure = complete_array_type (ptype, initial_value, do_default);

  /* We can create the array before the element type is complete, which
     means that we didn't have these two bits set in the original type
     either.  In completing the type, we are expected to propagate these
     bits.  See also complete_type which does the same thing for arrays
     of fixed size.  */
  type = *ptype;
  if (type != error_mark_node && TYPE_DOMAIN (type))
    {
      elt_type = TREE_TYPE (type);
      TYPE_NEEDS_CONSTRUCTING (type) = TYPE_NEEDS_CONSTRUCTING (elt_type);
      TYPE_HAS_NONTRIVIAL_DESTRUCTOR (type)
	= TYPE_HAS_NONTRIVIAL_DESTRUCTOR (elt_type);
    }

  return failure;
}

/* As above, but either give an error or reject zero-size arrays, depending
   on COMPLAIN.  */

int
cp_complete_array_type_or_error (tree *ptype, tree initial_value,
				 bool do_default, tsubst_flags_t complain)
{
  int failure;
  bool sfinae = !(complain & tf_error);
  /* In SFINAE context we can't be lenient about zero-size arrays.  */
  if (sfinae)
    ++pedantic;
  failure = cp_complete_array_type (ptype, initial_value, do_default);
  if (sfinae)
    --pedantic;
  if (failure)
    {
      if (sfinae)
	/* Not an error.  */;
      else if (failure == 1)
	error ("initializer fails to determine size of %qT", *ptype);
      else if (failure == 2)
	{
	  if (do_default)
	    error ("array size missing in %qT", *ptype);
	}
      else if (failure == 3)
	error ("zero-size array %qT", *ptype);
      *ptype = error_mark_node;
    }
  return failure;
}

/* Return zero if something is declared to be a member of type
   CTYPE when in the context of CUR_TYPE.  STRING is the error
   message to print in that case.  Otherwise, quietly return 1.  */

static int
member_function_or_else (tree ctype, tree cur_type, enum overload_flags flags)
{
  if (ctype && ctype != cur_type)
    {
      if (flags == DTOR_FLAG)
	error ("destructor for alien class %qT cannot be a member", ctype);
      else
	error ("constructor for alien class %qT cannot be a member", ctype);
      return 0;
    }
  return 1;
}

/* Subroutine of `grokdeclarator'.  */

/* Generate errors possibly applicable for a given set of specifiers.
   This is for ARM $7.1.2.  */

static void
bad_specifiers (tree object,
		enum bad_spec_place type,
		int virtualp,
		int quals,
		int inlinep,
		int friendp,
		int raises,
		const location_t* locations)
{
  switch (type)
    {
      case BSP_VAR:
	if (virtualp)
	  error_at (locations[ds_virtual],
		    "%qD declared as a %<virtual%> variable", object);
	if (quals)
	  error ("%<const%> and %<volatile%> function specifiers on "
	         "%qD invalid in variable declaration", object);
	break;
      case BSP_PARM:
	if (virtualp)
	  error_at (locations[ds_virtual],
		    "%qD declared as a %<virtual%> parameter", object);
	if (inlinep)
	  error_at (locations[ds_inline],
		    "%qD declared as an %<inline%> parameter", object);
	if (quals)
	  error ("%<const%> and %<volatile%> function specifiers on "
	  	 "%qD invalid in parameter declaration", object);
	break;
      case BSP_TYPE:
	if (virtualp)
	  error_at (locations[ds_virtual],
		    "%qD declared as a %<virtual%> type", object);
	if (inlinep)
	  error_at (locations[ds_inline],
		    "%qD declared as an %<inline%> type", object);
	if (quals)
	  error ("%<const%> and %<volatile%> function specifiers on "
	  	 "%qD invalid in type declaration", object);
	break;
      case BSP_FIELD:
	if (virtualp)
	  error_at (locations[ds_virtual],
		    "%qD declared as a %<virtual%> field", object);
	if (inlinep)
	  error_at (locations[ds_inline],
		    "%qD declared as an %<inline%> field", object);
	if (quals)
	  error ("%<const%> and %<volatile%> function specifiers on "
	  	 "%qD invalid in field declaration", object);
	break;
      default:
        gcc_unreachable();
    }
  if (friendp)
    error ("%q+D declared as a friend", object);
  if (raises
      && !flag_noexcept_type
      && (TREE_CODE (object) == TYPE_DECL
	  || (!TYPE_PTRFN_P (TREE_TYPE (object))
	      && !TYPE_REFFN_P (TREE_TYPE (object))
	      && !TYPE_PTRMEMFUNC_P (TREE_TYPE (object)))))
    error ("%q+D declared with an exception specification", object);
}

/* DECL is a member function or static data member and is presently
   being defined.  Check that the definition is taking place in a
   valid namespace.  */

static void
check_class_member_definition_namespace (tree decl)
{
  /* These checks only apply to member functions and static data
     members.  */
  gcc_assert (VAR_OR_FUNCTION_DECL_P (decl));
  /* We check for problems with specializations in pt.cc in
     check_specialization_namespace, where we can issue better
     diagnostics.  */
  if (processing_specialization)
    return;
  /* We check this in check_explicit_instantiation_namespace.  */
  if (processing_explicit_instantiation)
    return;
  /* [class.mfct]

     A member function definition that appears outside of the
     class definition shall appear in a namespace scope enclosing
     the class definition.

     [class.static.data]

     The definition for a static data member shall appear in a
     namespace scope enclosing the member's class definition.  */
  if (!is_ancestor (current_namespace, DECL_CONTEXT (decl)))
    permerror (input_location, "definition of %qD is not in namespace enclosing %qT",
	       decl, DECL_CONTEXT (decl));
}

/* Build a PARM_DECL for the "this" parameter of FN.  TYPE is the
   METHOD_TYPE for a non-static member function; QUALS are the
   cv-qualifiers that apply to the function.  */

tree
build_this_parm (tree fn, tree type, cp_cv_quals quals)
{
  tree this_type;
  tree qual_type;
  tree parm;
  cp_cv_quals this_quals;

  if (CLASS_TYPE_P (type))
    {
      this_type
	= cp_build_qualified_type (type, quals & ~TYPE_QUAL_RESTRICT);
      this_type = build_pointer_type (this_type);
    }
  else
    this_type = type_of_this_parm (type);
  /* The `this' parameter is implicitly `const'; it cannot be
     assigned to.  */
  this_quals = (quals & TYPE_QUAL_RESTRICT) | TYPE_QUAL_CONST;
  qual_type = cp_build_qualified_type (this_type, this_quals);
  parm = build_artificial_parm (fn, this_identifier, qual_type);
  cp_apply_type_quals_to_decl (this_quals, parm);
  return parm;
}

/* DECL is a static member function.  Complain if it was declared
   with function-cv-quals.  */

static void
check_static_quals (tree decl, cp_cv_quals quals)
{
  if (quals != TYPE_UNQUALIFIED)
    error ("static member function %q#D declared with type qualifiers",
	   decl);
}

// Check that FN takes no arguments and returns bool.
static void
check_concept_fn (tree fn)
{
  // A constraint is nullary.
  if (DECL_ARGUMENTS (fn))
    error_at (DECL_SOURCE_LOCATION (fn),
	      "concept %q#D declared with function parameters", fn);

  // The declared return type of the concept shall be bool, and
  // it shall not be deduced from it definition.
  tree type = TREE_TYPE (TREE_TYPE (fn));
  if (is_auto (type))
    error_at (DECL_SOURCE_LOCATION (fn),
	      "concept %q#D declared with a deduced return type", fn);
  else if (type != boolean_type_node)
    error_at (DECL_SOURCE_LOCATION (fn),
	      "concept %q#D with non-%<bool%> return type %qT", fn, type);
}

/* Helper function.  Replace the temporary this parameter injected
   during cp_finish_omp_declare_simd with the real this parameter.  */

static tree
declare_simd_adjust_this (tree *tp, int *walk_subtrees, void *data)
{
  tree this_parm = (tree) data;
  if (TREE_CODE (*tp) == PARM_DECL
      && DECL_NAME (*tp) == this_identifier
      && *tp != this_parm)
    *tp = this_parm;
  else if (TYPE_P (*tp))
    *walk_subtrees = 0;
  return NULL_TREE;
}

/* CTYPE is class type, or null if non-class.
   TYPE is type this FUNCTION_DECL should have, either FUNCTION_TYPE
   or METHOD_TYPE.
   DECLARATOR is the function's name.
   PARMS is a chain of PARM_DECLs for the function.
   VIRTUALP is truthvalue of whether the function is virtual or not.
   FLAGS are to be passed through to `grokclassfn'.
   QUALS are qualifiers indicating whether the function is `const'
   or `volatile'.
   RAISES is a list of exceptions that this function can raise.
   CHECK is 1 if we must find this method in CTYPE, 0 if we should
   not look, and -1 if we should not call `grokclassfn' at all.

   SFK is the kind of special function (if any) for the new function.

   Returns `NULL_TREE' if something goes wrong, after issuing
   applicable error messages.  */

static tree
grokfndecl (tree ctype,
	    tree type,
	    tree declarator,
	    tree parms,
	    tree orig_declarator,
	    const cp_decl_specifier_seq *declspecs,
	    tree decl_reqs,
	    int virtualp,
	    enum overload_flags flags,
	    cp_cv_quals quals,
	    cp_ref_qualifier rqual,
	    tree raises,
	    int check,
	    int friendp,
	    int publicp,
	    int inlinep,
	    bool deletedp,
	    special_function_kind sfk,
	    bool funcdef_flag,
	    bool late_return_type_p,
	    int template_count,
	    tree in_namespace,
	    tree* attrlist,
	    location_t location)
{
  tree decl;
  int staticp = ctype && TREE_CODE (type) == FUNCTION_TYPE;
  tree t;

  if (location == UNKNOWN_LOCATION)
    location = input_location;

  /* Was the concept specifier present?  */
  bool concept_p = inlinep & 4;

  /* Concept declarations must have a corresponding definition.  */
  if (concept_p && !funcdef_flag)
    {
      error_at (location, "concept %qD has no definition", declarator);
      return NULL_TREE;
    }

  type = build_cp_fntype_variant (type, rqual, raises, late_return_type_p);

  decl = build_lang_decl_loc (location, FUNCTION_DECL, declarator, type);

  /* Set the constraints on the declaration. */
  if (flag_concepts)
    {
      tree tmpl_reqs = NULL_TREE;
      tree ctx = friendp ? current_class_type : ctype;
      bool block_local = TREE_CODE (current_scope ()) == FUNCTION_DECL;
      bool memtmpl = (!block_local
		      && (current_template_depth
			  > template_class_depth (ctx)));
      if (memtmpl)
	{
	  if (!current_template_parms)
	    /* If there are no template parameters, something must have
	       gone wrong.  */
	    gcc_assert (seen_error ());
	  else
	    tmpl_reqs = TEMPLATE_PARMS_CONSTRAINTS (current_template_parms);
	}
      tree ci = build_constraints (tmpl_reqs, decl_reqs);
      if (concept_p && ci)
        {
          error_at (location, "a function concept cannot be constrained");
          ci = NULL_TREE;
        }
      /* C++20 CA378: Remove non-templated constrained functions.  */
      if (ci
	  && (block_local
	      || (!flag_concepts_ts
		  && (!processing_template_decl
		      || (friendp && !memtmpl && !funcdef_flag)))))
	{
	  error_at (location, "constraints on a non-templated function");
	  ci = NULL_TREE;
	}
      set_constraints (decl, ci);
    }

  if (TREE_CODE (type) == METHOD_TYPE)
    {
      tree parm = build_this_parm (decl, type, quals);
      DECL_CHAIN (parm) = parms;
      parms = parm;

      /* Allocate space to hold the vptr bit if needed.  */
      SET_DECL_ALIGN (decl, MINIMUM_METHOD_BOUNDARY);
    }

  DECL_ARGUMENTS (decl) = parms;
  for (t = parms; t; t = DECL_CHAIN (t))
    DECL_CONTEXT (t) = decl;

  /* Propagate volatile out from type to decl.  */
  if (TYPE_VOLATILE (type))
    TREE_THIS_VOLATILE (decl) = 1;

  /* Setup decl according to sfk.  */
  switch (sfk)
    {
    case sfk_constructor:
    case sfk_copy_constructor:
    case sfk_move_constructor:
      DECL_CXX_CONSTRUCTOR_P (decl) = 1;
      DECL_NAME (decl) = ctor_identifier;
      break;
    case sfk_destructor:
      DECL_CXX_DESTRUCTOR_P (decl) = 1;
      DECL_NAME (decl) = dtor_identifier;
      break;
    default:
      break;
    }

  if (friendp && TREE_CODE (orig_declarator) == TEMPLATE_ID_EXPR)
    {
      if (funcdef_flag)
	error_at (location,
		  "defining explicit specialization %qD in friend declaration",
		  orig_declarator);
      else
	{
	  tree fns = TREE_OPERAND (orig_declarator, 0);
	  tree args = TREE_OPERAND (orig_declarator, 1);

	  if (PROCESSING_REAL_TEMPLATE_DECL_P ())
	    {
	      /* Something like `template <class T> friend void f<T>()'.  */
	      error_at (location,
			"invalid use of template-id %qD in declaration "
			"of primary template",
			orig_declarator);
	      return NULL_TREE;
	    }


	  /* A friend declaration of the form friend void f<>().  Record
	     the information in the TEMPLATE_ID_EXPR.  */
	  SET_DECL_IMPLICIT_INSTANTIATION (decl);

	  gcc_assert (identifier_p (fns) || OVL_P (fns));
	  DECL_TEMPLATE_INFO (decl) = build_template_info (fns, args);

	  for (t = TYPE_ARG_TYPES (TREE_TYPE (decl)); t; t = TREE_CHAIN (t))
	    if (TREE_PURPOSE (t)
		&& TREE_CODE (TREE_PURPOSE (t)) == DEFERRED_PARSE)
	    {
	      error_at (defparse_location (TREE_PURPOSE (t)),
			"default arguments are not allowed in declaration "
			"of friend template specialization %qD",
			decl);
	      return NULL_TREE;
	    }

	  if (inlinep & 1)
	    {
	      error_at (declspecs->locations[ds_inline],
			"%<inline%> is not allowed in declaration of friend "
			"template specialization %qD",
			decl);
	      return NULL_TREE;
	    }
	}
    }

  /* C++17 11.3.6/4: "If a friend declaration specifies a default argument
     expression, that declaration shall be a definition..."  */
  if (friendp && !funcdef_flag)
    {
      for (tree t = FUNCTION_FIRST_USER_PARMTYPE (decl);
	   t && t != void_list_node; t = TREE_CHAIN (t))
	if (TREE_PURPOSE (t))
	  {
	    permerror (DECL_SOURCE_LOCATION (decl),
		       "friend declaration of %qD specifies default "
		       "arguments and isn%'t a definition", decl);
	    break;
	  }
    }

  /* If this decl has namespace scope, set that up.  */
  if (in_namespace)
    set_decl_namespace (decl, in_namespace, friendp);
  else if (ctype)
    DECL_CONTEXT (decl) = ctype;
  else
    DECL_CONTEXT (decl) = FROB_CONTEXT (current_decl_namespace ());

  /* `main' and builtins have implicit 'C' linkage.  */
  if (ctype == NULL_TREE
      && DECL_FILE_SCOPE_P (decl)
      && current_lang_name == lang_name_cplusplus
      && (MAIN_NAME_P (declarator)
	  || (IDENTIFIER_LENGTH (declarator) > 10
	      && IDENTIFIER_POINTER (declarator)[0] == '_'
	      && IDENTIFIER_POINTER (declarator)[1] == '_'
	      && startswith (IDENTIFIER_POINTER (declarator) + 2,
			     "builtin_"))
	  || (targetcm.cxx_implicit_extern_c
	      && (targetcm.cxx_implicit_extern_c
		  (IDENTIFIER_POINTER (declarator))))))
    SET_DECL_LANGUAGE (decl, lang_c);

  /* Should probably propagate const out from type to decl I bet (mrs).  */
  if (staticp)
    {
      DECL_STATIC_FUNCTION_P (decl) = 1;
      DECL_CONTEXT (decl) = ctype;
    }

  if (deletedp)
    DECL_DELETED_FN (decl) = 1;

  if (ctype && funcdef_flag)
    check_class_member_definition_namespace (decl);

  if (ctype == NULL_TREE && DECL_MAIN_P (decl))
    {
      if (PROCESSING_REAL_TEMPLATE_DECL_P())
	error_at (location, "cannot declare %<::main%> to be a template");
      if (inlinep & 1)
	error_at (declspecs->locations[ds_inline],
		  "cannot declare %<::main%> to be inline");
      if (inlinep & 2)
	error_at (declspecs->locations[ds_constexpr],
		  "cannot declare %<::main%> to be %qs", "constexpr");
      if (inlinep & 8)
	error_at (declspecs->locations[ds_consteval],
		  "cannot declare %<::main%> to be %qs", "consteval");
      if (!publicp)
	error_at (location, "cannot declare %<::main%> to be static");
      inlinep = 0;
      publicp = 1;
    }

  /* Members of anonymous types and local classes have no linkage; make
     them internal.  If a typedef is made later, this will be changed.  */
  if (ctype && (!TREE_PUBLIC (TYPE_MAIN_DECL (ctype))
		|| decl_function_context (TYPE_MAIN_DECL (ctype))))
    publicp = 0;

  if (publicp && cxx_dialect == cxx98)
    {
      /* [basic.link]: A name with no linkage (notably, the name of a class
	 or enumeration declared in a local scope) shall not be used to
	 declare an entity with linkage.

	 DR 757 relaxes this restriction for C++0x.  */
      no_linkage_error (decl);
    }

  TREE_PUBLIC (decl) = publicp;
  if (! publicp)
    {
      DECL_INTERFACE_KNOWN (decl) = 1;
      DECL_NOT_REALLY_EXTERN (decl) = 1;
    }

  /* If the declaration was declared inline, mark it as such.  */
  if (inlinep)
    {
      DECL_DECLARED_INLINE_P (decl) = 1;
      if (publicp)
	DECL_COMDAT (decl) = 1;
    }
  if (inlinep & 2)
    DECL_DECLARED_CONSTEXPR_P (decl) = true;
  else if (inlinep & 8)
    {
      DECL_DECLARED_CONSTEXPR_P (decl) = true;
      SET_DECL_IMMEDIATE_FUNCTION_P (decl);
    }

  // If the concept declaration specifier was found, check
  // that the declaration satisfies the necessary requirements.
  if (concept_p)
    {
      DECL_DECLARED_CONCEPT_P (decl) = true;
      check_concept_fn (decl);
    }

  DECL_EXTERNAL (decl) = 1;
  if (TREE_CODE (type) == FUNCTION_TYPE)
    {
      if (quals || rqual)
	TREE_TYPE (decl) = apply_memfn_quals (TREE_TYPE (decl),
					      TYPE_UNQUALIFIED,
					      REF_QUAL_NONE);

      if (quals)
	{
	  error (ctype
		 ? G_("static member function %qD cannot have cv-qualifier")
		 : G_("non-member function %qD cannot have cv-qualifier"),
		 decl);
	  quals = TYPE_UNQUALIFIED;
	}

      if (rqual)
	{
	  error (ctype
		 ? G_("static member function %qD cannot have ref-qualifier")
		 : G_("non-member function %qD cannot have ref-qualifier"),
		 decl);
	  rqual = REF_QUAL_NONE;
	}
    }

  if (deduction_guide_p (decl))
    {
      tree type = TREE_TYPE (DECL_NAME (decl));
      if (in_namespace == NULL_TREE
	  && CP_DECL_CONTEXT (decl) != CP_TYPE_CONTEXT (type))
	{
	  error_at (location, "deduction guide %qD must be declared in the "
			      "same scope as %qT", decl, type);
	  inform (location_of (type), "  declared here");
	  return NULL_TREE;
	}
      if (DECL_CLASS_SCOPE_P (decl)
	  && current_access_specifier != declared_access (TYPE_NAME (type)))
	{
	  error_at (location, "deduction guide %qD must have the same access "
			      "as %qT", decl, type);
	  inform (location_of (type), "  declared here");
	}
      if (funcdef_flag)
	error_at (location,
		  "deduction guide %qD must not have a function body", decl);
    }
  else if (IDENTIFIER_ANY_OP_P (DECL_NAME (decl))
	   && !grok_op_properties (decl, /*complain=*/true))
    return NULL_TREE;
  else if (UDLIT_OPER_P (DECL_NAME (decl)))
    {
      bool long_long_unsigned_p;
      bool long_double_p;
      const char *suffix = NULL;
      /* [over.literal]/6: Literal operators shall not have C linkage. */
      if (DECL_LANGUAGE (decl) == lang_c)
	{
	  error_at (location, "literal operator with C linkage");
	  maybe_show_extern_c_location ();
	  return NULL_TREE;
	}

      if (DECL_NAMESPACE_SCOPE_P (decl))
	{
	  if (!check_literal_operator_args (decl, &long_long_unsigned_p,
					    &long_double_p))
	    {
	      error_at (location, "%qD has invalid argument list", decl);
	      return NULL_TREE;
	    }

	  suffix = UDLIT_OP_SUFFIX (DECL_NAME (decl));
	  if (long_long_unsigned_p)
	    {
	      if (cpp_interpret_int_suffix (parse_in, suffix, strlen (suffix)))
		warning_at (location, 0, "integer suffix %qs"
			    " shadowed by implementation", suffix);
	    }
	  else if (long_double_p)
	    {
	      if (cpp_interpret_float_suffix (parse_in, suffix, strlen (suffix)))
		warning_at (location, 0, "floating-point suffix %qs"
			    " shadowed by implementation", suffix);
	    }
	  /* 17.6.3.3.5  */
	  if (suffix[0] != '_'
	      && !current_function_decl && !(friendp && !funcdef_flag))
	    warning_at (location, OPT_Wliteral_suffix,
			"literal operator suffixes not preceded by %<_%>"
			" are reserved for future standardization");
	}
      else
	{
	  error_at (location, "%qD must be a non-member function", decl);
	  return NULL_TREE;
	}
    }

  if (funcdef_flag)
    /* Make the init_value nonzero so pushdecl knows this is not
       tentative.  error_mark_node is replaced later with the BLOCK.  */
    DECL_INITIAL (decl) = error_mark_node;

  if (TYPE_NOTHROW_P (type) || nothrow_libfn_p (decl))
    TREE_NOTHROW (decl) = 1;

  if (flag_openmp || flag_openmp_simd)
    {
      /* Adjust "omp declare simd" attributes.  */
      tree ods = lookup_attribute ("omp declare simd", *attrlist);
      if (ods)
	{
	  tree attr;
	  for (attr = ods; attr;
	       attr = lookup_attribute ("omp declare simd", TREE_CHAIN (attr)))
	    {
	      if (TREE_CODE (type) == METHOD_TYPE)
		walk_tree (&TREE_VALUE (attr), declare_simd_adjust_this,
			   DECL_ARGUMENTS (decl), NULL);
	      if (TREE_VALUE (attr) != NULL_TREE)
		{
		  tree cl = TREE_VALUE (TREE_VALUE (attr));
		  cl = c_omp_declare_simd_clauses_to_numbers
						(DECL_ARGUMENTS (decl), cl);
		  if (cl)
		    TREE_VALUE (TREE_VALUE (attr)) = cl;
		  else
		    TREE_VALUE (attr) = NULL_TREE;
		}
	    }
	}
    }

  /* Caller will do the rest of this.  */
  if (check < 0)
    return decl;

  if (ctype != NULL_TREE)
    grokclassfn (ctype, decl, flags);

  /* 12.4/3  */
  if (cxx_dialect >= cxx11
      && DECL_DESTRUCTOR_P (decl)
      && !TYPE_BEING_DEFINED (DECL_CONTEXT (decl))
      && !processing_template_decl)
    deduce_noexcept_on_destructor (decl);

  set_originating_module (decl);

  decl = check_explicit_specialization (orig_declarator, decl,
					template_count,
					2 * funcdef_flag +
					4 * (friendp != 0) +
	                                8 * concept_p,
					*attrlist);
  if (decl == error_mark_node)
    return NULL_TREE;

  if (DECL_STATIC_FUNCTION_P (decl))
    check_static_quals (decl, quals);

  if (attrlist)
    {
      cplus_decl_attributes (&decl, *attrlist, 0);
      *attrlist = NULL_TREE;
    }

  /* Check main's type after attributes have been applied.  */
  if (ctype == NULL_TREE && DECL_MAIN_P (decl))
    {
      if (!same_type_p (TREE_TYPE (TREE_TYPE (decl)),
			integer_type_node))
	{
	  tree oldtypeargs = TYPE_ARG_TYPES (TREE_TYPE (decl));
	  tree newtype;
	  error_at (declspecs->locations[ds_type_spec],
		    "%<::main%> must return %<int%>");
	  newtype = build_function_type (integer_type_node, oldtypeargs);
	  TREE_TYPE (decl) = newtype;
	}
      if (warn_main)
	check_main_parameter_types (decl);
    }

  if (ctype != NULL_TREE && check)
    {
      tree old_decl = check_classfn (ctype, decl,
				     (current_template_depth
				      > template_class_depth (ctype))
				     ? current_template_parms
				     : NULL_TREE);

      if (old_decl == error_mark_node)
	return NULL_TREE;

      if (old_decl)
	{
	  tree ok;
	  tree pushed_scope;

	  if (TREE_CODE (old_decl) == TEMPLATE_DECL)
	    /* Because grokfndecl is always supposed to return a
	       FUNCTION_DECL, we pull out the DECL_TEMPLATE_RESULT
	       here.  We depend on our callers to figure out that its
	       really a template that's being returned.  */
	    old_decl = DECL_TEMPLATE_RESULT (old_decl);

	  if (DECL_STATIC_FUNCTION_P (old_decl)
	      && TREE_CODE (TREE_TYPE (decl)) == METHOD_TYPE)
	    {
	      /* Remove the `this' parm added by grokclassfn.  */
	      revert_static_member_fn (decl);
	      check_static_quals (decl, quals);
	    }
	  if (DECL_ARTIFICIAL (old_decl))
	    {
	      error ("definition of implicitly-declared %qD", old_decl);
	      return NULL_TREE;
	    }
	  else if (DECL_DEFAULTED_FN (old_decl))
	    {
	      error ("definition of explicitly-defaulted %q+D", decl);
	      inform (DECL_SOURCE_LOCATION (old_decl),
		      "%q#D explicitly defaulted here", old_decl);
	      return NULL_TREE;
	    }

	  /* Since we've smashed OLD_DECL to its
	     DECL_TEMPLATE_RESULT, we must do the same to DECL.  */
	  if (TREE_CODE (decl) == TEMPLATE_DECL)
	    decl = DECL_TEMPLATE_RESULT (decl);

	  /* Attempt to merge the declarations.  This can fail, in
	     the case of some invalid specialization declarations.  */
	  pushed_scope = push_scope (ctype);
	  ok = duplicate_decls (decl, old_decl);
	  if (pushed_scope)
	    pop_scope (pushed_scope);
	  if (!ok)
	    {
	      error ("no %q#D member function declared in class %qT",
		     decl, ctype);
	      return NULL_TREE;
	    }
	  if (ok == error_mark_node)
	    return NULL_TREE;
	  return old_decl;
	}
    }

  if (DECL_CONSTRUCTOR_P (decl) && !grok_ctor_properties (ctype, decl))
    return NULL_TREE;

  if (ctype == NULL_TREE || check)
    return decl;

  if (virtualp)
    DECL_VIRTUAL_P (decl) = 1;

  return decl;
}

/* decl is a FUNCTION_DECL.
   specifiers are the parsed virt-specifiers.

   Set flags to reflect the virt-specifiers.

   Returns decl.  */

static tree
set_virt_specifiers (tree decl, cp_virt_specifiers specifiers)
{
  if (decl == NULL_TREE)
    return decl;
  if (specifiers & VIRT_SPEC_OVERRIDE)
    DECL_OVERRIDE_P (decl) = 1;
  if (specifiers & VIRT_SPEC_FINAL)
    DECL_FINAL_P (decl) = 1;
  return decl;
}

/* DECL is a VAR_DECL for a static data member.  Set flags to reflect
   the linkage that DECL will receive in the object file.  */

static void
set_linkage_for_static_data_member (tree decl)
{
  /* A static data member always has static storage duration and
     external linkage.  Note that static data members are forbidden in
     local classes -- the only situation in which a class has
     non-external linkage.  */
  TREE_PUBLIC (decl) = 1;
  TREE_STATIC (decl) = 1;
  /* For non-template classes, static data members are always put
     out in exactly those files where they are defined, just as
     with ordinary namespace-scope variables.  */
  if (!processing_template_decl)
    DECL_INTERFACE_KNOWN (decl) = 1;
}

/* Create a VAR_DECL named NAME with the indicated TYPE.

   If SCOPE is non-NULL, it is the class type or namespace containing
   the variable.  If SCOPE is NULL, the variable should is created in
   the innermost enclosing scope.  */

static tree
grokvardecl (tree type,
	     tree name,
	     tree orig_declarator,
	     const cp_decl_specifier_seq *declspecs,
	     int initialized,
	     int type_quals,
	     int inlinep,
	     bool conceptp,
	     int template_count,
	     tree scope,
	     location_t location)
{
  tree decl;
  tree explicit_scope;

  gcc_assert (!name || identifier_p (name));

  bool constp = (type_quals & TYPE_QUAL_CONST) != 0;
  bool volatilep = (type_quals & TYPE_QUAL_VOLATILE) != 0;

  /* Compute the scope in which to place the variable, but remember
     whether or not that scope was explicitly specified by the user.   */
  explicit_scope = scope;
  if (!scope)
    {
      /* An explicit "extern" specifier indicates a namespace-scope
	 variable.  */
      if (declspecs->storage_class == sc_extern)
	scope = current_decl_namespace ();
      else if (!at_function_scope_p ())
	scope = current_scope ();
    }

  if (scope
      && (/* If the variable is a namespace-scope variable declared in a
	     template, we need DECL_LANG_SPECIFIC.  */
	  (TREE_CODE (scope) == NAMESPACE_DECL && processing_template_decl)
	  /* Similarly for namespace-scope variables with language linkage
	     other than C++.  */
	  || (TREE_CODE (scope) == NAMESPACE_DECL
	      && current_lang_name != lang_name_cplusplus)
	  /* Similarly for static data members.  */
	  || TYPE_P (scope)
	  /* Similarly for explicit specializations.  */
	  || (orig_declarator
	      && TREE_CODE (orig_declarator) == TEMPLATE_ID_EXPR)))
    decl = build_lang_decl_loc (location, VAR_DECL, name, type);
  else
    decl = build_decl (location, VAR_DECL, name, type);

  if (explicit_scope && TREE_CODE (explicit_scope) == NAMESPACE_DECL)
    set_decl_namespace (decl, explicit_scope, 0);
  else
    DECL_CONTEXT (decl) = FROB_CONTEXT (scope);

  if (declspecs->storage_class == sc_extern)
    {
      DECL_THIS_EXTERN (decl) = 1;
      DECL_EXTERNAL (decl) = !initialized;
    }

  if (DECL_CLASS_SCOPE_P (decl))
    {
      set_linkage_for_static_data_member (decl);
      /* This function is only called with out-of-class definitions.  */
      DECL_EXTERNAL (decl) = 0;
      check_class_member_definition_namespace (decl);
    }
  /* At top level, either `static' or no s.c. makes a definition
     (perhaps tentative), and absence of `static' makes it public.  */
  else if (toplevel_bindings_p ())
    {
      TREE_PUBLIC (decl) = (declspecs->storage_class != sc_static
			    && (DECL_THIS_EXTERN (decl)
				|| ! constp
				|| volatilep
				|| inlinep));
      TREE_STATIC (decl) = ! DECL_EXTERNAL (decl);
    }
  /* Not at top level, only `static' makes a static definition.  */
  else
    {
      TREE_STATIC (decl) = declspecs->storage_class == sc_static;
      TREE_PUBLIC (decl) = DECL_EXTERNAL (decl);
    }

  set_originating_module (decl);

  if (decl_spec_seq_has_spec_p (declspecs, ds_thread))
    {
      if (DECL_EXTERNAL (decl) || TREE_STATIC (decl))
	{
	  CP_DECL_THREAD_LOCAL_P (decl) = true;
	  if (!processing_template_decl)
	    set_decl_tls_model (decl, decl_default_tls_model (decl));
	}
      if (declspecs->gnu_thread_keyword_p)
	SET_DECL_GNU_TLS_P (decl);
    }

  /* If the type of the decl has no linkage, make sure that we'll
     notice that in mark_used.  */
  if (cxx_dialect > cxx98
      && decl_linkage (decl) != lk_none
      && DECL_LANG_SPECIFIC (decl) == NULL
      && !DECL_EXTERN_C_P (decl)
      && no_linkage_check (TREE_TYPE (decl), /*relaxed_p=*/false))
    retrofit_lang_decl (decl);

  if (TREE_PUBLIC (decl))
    {
      /* [basic.link]: A name with no linkage (notably, the name of a class
	 or enumeration declared in a local scope) shall not be used to
	 declare an entity with linkage.

	 DR 757 relaxes this restriction for C++0x.  */
      if (cxx_dialect < cxx11)
	no_linkage_error (decl);
    }
  else
    DECL_INTERFACE_KNOWN (decl) = 1;

  if (DECL_NAME (decl)
      && MAIN_NAME_P (DECL_NAME (decl))
      && scope == global_namespace)
    error_at (DECL_SOURCE_LOCATION (decl),
	      "cannot declare %<::main%> to be a global variable");

  /* Check that the variable can be safely declared as a concept.
     Note that this also forbids explicit specializations.  */
  if (conceptp)
    {
      if (!processing_template_decl)
        {
          error_at (declspecs->locations[ds_concept],
		    "a non-template variable cannot be %<concept%>");
          return NULL_TREE;
        }
      else if (!at_namespace_scope_p ())
	{
	  error_at (declspecs->locations[ds_concept],
		    "concept must be defined at namespace scope");
	  return NULL_TREE;
	}
      else
        DECL_DECLARED_CONCEPT_P (decl) = true;
      if (!same_type_ignoring_top_level_qualifiers_p (type, boolean_type_node))
	error_at (declspecs->locations[ds_type_spec],
		  "concept must have type %<bool%>");
      if (TEMPLATE_PARMS_CONSTRAINTS (current_template_parms))
        {
          error_at (location, "a variable concept cannot be constrained");
          TEMPLATE_PARMS_CONSTRAINTS (current_template_parms) = NULL_TREE;
        }
    }
  else if (flag_concepts
	   && current_template_depth > template_class_depth (scope))
    {
      tree reqs = TEMPLATE_PARMS_CONSTRAINTS (current_template_parms);
      tree ci = build_constraints (reqs, NULL_TREE);

      set_constraints (decl, ci);
    }

  // Handle explicit specializations and instantiations of variable templates.
  if (orig_declarator)
    decl = check_explicit_specialization (orig_declarator, decl,
					  template_count, conceptp * 8);

  return decl != error_mark_node ? decl : NULL_TREE;
}

/* Create and return a canonical pointer to member function type, for
   TYPE, which is a POINTER_TYPE to a METHOD_TYPE.  */

tree
build_ptrmemfunc_type (tree type)
{
  tree field, fields;
  tree t;

  if (type == error_mark_node)
    return type;

  /* Make sure that we always have the unqualified pointer-to-member
     type first.  */
  if (cp_cv_quals quals = cp_type_quals (type))
    {
      tree unqual = build_ptrmemfunc_type (TYPE_MAIN_VARIANT (type));
      return cp_build_qualified_type (unqual, quals);
    }

  /* If a canonical type already exists for this type, use it.  We use
     this method instead of type_hash_canon, because it only does a
     simple equality check on the list of field members.  */

  t = TYPE_PTRMEMFUNC_TYPE (type);
  if (t)
    return t;

  t = make_node (RECORD_TYPE);

  /* Let the front end know this is a pointer to member function.  */
  TYPE_PTRMEMFUNC_FLAG (t) = 1;

  field = build_decl (input_location, FIELD_DECL, pfn_identifier, type);
  DECL_NONADDRESSABLE_P (field) = 1;
  fields = field;

  field = build_decl (input_location, FIELD_DECL, delta_identifier, 
		      delta_type_node);
  DECL_NONADDRESSABLE_P (field) = 1;
  DECL_CHAIN (field) = fields;
  fields = field;

  finish_builtin_struct (t, "__ptrmemfunc_type", fields, ptr_type_node);

  /* Zap out the name so that the back end will give us the debugging
     information for this anonymous RECORD_TYPE.  */
  TYPE_NAME (t) = NULL_TREE;

  /* Cache this pointer-to-member type so that we can find it again
     later.  */
  TYPE_PTRMEMFUNC_TYPE (type) = t;

  if (TYPE_STRUCTURAL_EQUALITY_P (type))
    SET_TYPE_STRUCTURAL_EQUALITY (t);
  else if (TYPE_CANONICAL (type) != type)
    TYPE_CANONICAL (t) = build_ptrmemfunc_type (TYPE_CANONICAL (type));

  return t;
}

/* Create and return a pointer to data member type.  */

tree
build_ptrmem_type (tree class_type, tree member_type)
{
  if (TREE_CODE (member_type) == METHOD_TYPE)
    {
      cp_cv_quals quals = type_memfn_quals (member_type);
      cp_ref_qualifier rqual = type_memfn_rqual (member_type);
      member_type = build_memfn_type (member_type, class_type, quals, rqual);
      return build_ptrmemfunc_type (build_pointer_type (member_type));
    }
  else
    {
      gcc_assert (TREE_CODE (member_type) != FUNCTION_TYPE);
      return build_offset_type (class_type, member_type);
    }
}

/* DECL is a VAR_DECL defined in-class, whose TYPE is also given.
   Check to see that the definition is valid.  Issue appropriate error
   messages.  */

static void
check_static_variable_definition (tree decl, tree type)
{
  /* Avoid redundant diagnostics on out-of-class definitions.  */
  if (!current_class_type || !TYPE_BEING_DEFINED (current_class_type))
    ;
  /* Can't check yet if we don't know the type.  */
  else if (dependent_type_p (type))
    ;
  /* If DECL is declared constexpr, we'll do the appropriate checks
     in check_initializer.  Similarly for inline static data members.  */
  else if (DECL_P (decl)
      && (DECL_DECLARED_CONSTEXPR_P (decl)
	  || DECL_VAR_DECLARED_INLINE_P (decl)))
    ;
  else if (cxx_dialect >= cxx11 && !INTEGRAL_OR_ENUMERATION_TYPE_P (type))
    {
      if (!COMPLETE_TYPE_P (type))
	error_at (DECL_SOURCE_LOCATION (decl),
		  "in-class initialization of static data member %q#D of "
		  "incomplete type", decl);
      else if (literal_type_p (type))
	permerror (DECL_SOURCE_LOCATION (decl),
		   "%<constexpr%> needed for in-class initialization of "
		   "static data member %q#D of non-integral type", decl);
      else
	error_at (DECL_SOURCE_LOCATION (decl),
		  "in-class initialization of static data member %q#D of "
		  "non-literal type", decl);
    }
  /* Motion 10 at San Diego: If a static const integral data member is
     initialized with an integral constant expression, the initializer
     may appear either in the declaration (within the class), or in
     the definition, but not both.  If it appears in the class, the
     member is a member constant.  The file-scope definition is always
     required.  */
  else if (!ARITHMETIC_TYPE_P (type) && TREE_CODE (type) != ENUMERAL_TYPE)
    error_at (DECL_SOURCE_LOCATION (decl),
	      "invalid in-class initialization of static data member "
	      "of non-integral type %qT",
	      type);
  else if (!CP_TYPE_CONST_P (type))
    error_at (DECL_SOURCE_LOCATION (decl),
	      "ISO C++ forbids in-class initialization of non-const "
	      "static member %qD",
	      decl);
  else if (!INTEGRAL_OR_ENUMERATION_TYPE_P (type))
    pedwarn (DECL_SOURCE_LOCATION (decl), OPT_Wpedantic,
	     "ISO C++ forbids initialization of member constant "
	     "%qD of non-integral type %qT", decl, type);
}

/* *expr_p is part of the TYPE_SIZE of a variably-sized array.  If any
   SAVE_EXPRs in *expr_p wrap expressions with side-effects, break those
   expressions out into temporary variables so that walk_tree doesn't
   step into them (c++/15764).  */

static tree
stabilize_save_expr_r (tree *expr_p, int *walk_subtrees, void *data)
{
  hash_set<tree> *pset = (hash_set<tree> *)data;
  tree expr = *expr_p;
  if (TREE_CODE (expr) == SAVE_EXPR)
    {
      tree op = TREE_OPERAND (expr, 0);
      cp_walk_tree (&op, stabilize_save_expr_r, data, pset);
      if (TREE_SIDE_EFFECTS (op))
	TREE_OPERAND (expr, 0) = get_temp_regvar (TREE_TYPE (op), op);
      *walk_subtrees = 0;
    }
  else if (!EXPR_P (expr) || !TREE_SIDE_EFFECTS (expr))
    *walk_subtrees = 0;
  return NULL;
}

/* Entry point for the above.  */

static void
stabilize_vla_size (tree size)
{
  hash_set<tree> pset;
  /* Break out any function calls into temporary variables.  */
  cp_walk_tree (&size, stabilize_save_expr_r, &pset, &pset);
}

/* Reduce a SIZEOF_EXPR to its value.  */

tree
fold_sizeof_expr (tree t)
{
  tree r;
  if (SIZEOF_EXPR_TYPE_P (t))
    r = cxx_sizeof_or_alignof_type (EXPR_LOCATION (t),
				    TREE_TYPE (TREE_OPERAND (t, 0)),
				    SIZEOF_EXPR, false, false);
  else if (TYPE_P (TREE_OPERAND (t, 0)))
    r = cxx_sizeof_or_alignof_type (EXPR_LOCATION (t),
				    TREE_OPERAND (t, 0), SIZEOF_EXPR,
				    false, false);
  else
    r = cxx_sizeof_or_alignof_expr (EXPR_LOCATION (t),
				    TREE_OPERAND (t, 0), SIZEOF_EXPR,
				    false, false);
  if (r == error_mark_node)
    r = size_one_node;
  return r;
}

/* Given the SIZE (i.e., number of elements) in an array, compute
   an appropriate index type for the array.  If non-NULL, NAME is
   the name of the entity being declared.  */

static tree
compute_array_index_type_loc (location_t name_loc, tree name, tree size,
			      tsubst_flags_t complain)
{
  if (error_operand_p (size))
    return error_mark_node;

  /* The type of the index being computed.  */
  tree itype;

  /* The original numeric size as seen in the source code before
     conversion to size_t.  */
  tree origsize = size;

  location_t loc = cp_expr_loc_or_loc (size, name ? name_loc : input_location);

  if (!type_dependent_expression_p (size))
    {
      origsize = size = mark_rvalue_use (size);

      if (cxx_dialect < cxx11 && TREE_CODE (size) == NOP_EXPR
	  && TREE_SIDE_EFFECTS (size))
	/* In C++98, we mark a non-constant array bound with a magic
	   NOP_EXPR with TREE_SIDE_EFFECTS; don't fold in that case.  */;
      else
	{
	  size = build_converted_constant_expr (size_type_node, size, complain);
	  /* Pedantically a constant expression is required here and so
	     __builtin_is_constant_evaluated () should fold to true if it
	     is successfully folded into a constant.  */
	  size = fold_non_dependent_expr (size, complain,
					  /*manifestly_const_eval=*/true);

	  if (!TREE_CONSTANT (size))
	    size = origsize;
	}

      if (error_operand_p (size))
	return error_mark_node;

      /* The array bound must be an integer type.  */
      tree type = TREE_TYPE (size);
      if (!INTEGRAL_OR_UNSCOPED_ENUMERATION_TYPE_P (type))
	{
	  if (!(complain & tf_error))
	    return error_mark_node;
	  if (name)
	    error_at (loc, "size of array %qD has non-integral type %qT",
		      name, type);
	  else
	    error_at (loc, "size of array has non-integral type %qT", type);
	  size = integer_one_node;
	}
    }

  /* A type is dependent if it is...an array type constructed from any
     dependent type or whose size is specified by a constant expression
     that is value-dependent.  */
  /* We can only call value_dependent_expression_p on integral constant
     expressions.  */
  if (processing_template_decl
      && potential_constant_expression (size)
      && value_dependent_expression_p (size))
    {
      /* Just build the index type and mark that it requires
	 structural equality checks.  */
    in_template:
      itype = build_index_type (build_min (MINUS_EXPR, sizetype,
					   size, size_one_node));
      TYPE_DEPENDENT_P (itype) = 1;
      TYPE_DEPENDENT_P_VALID (itype) = 1;
      SET_TYPE_STRUCTURAL_EQUALITY (itype);
      return itype;
    }

  if (TREE_CODE (size) != INTEGER_CST)
    {
      tree folded = cp_fully_fold (size);
      if (TREE_CODE (folded) == INTEGER_CST)
	{
	  if (name)
	    pedwarn (loc, OPT_Wpedantic, "size of array %qD is not an "
		     "integral constant-expression", name);
	  else
	    pedwarn (loc, OPT_Wpedantic,
		     "size of array is not an integral constant-expression");
	}
      if (TREE_CONSTANT (size) && !TREE_CONSTANT (folded))
	/* We might have lost the TREE_CONSTANT flag e.g. when we are
	   folding a conversion from a pointer to integral type.  In that
	   case issue an error below and don't treat this as a VLA.  */;
      else
	/* Use the folded result for VLAs, too; it will have resolved
	   SIZEOF_EXPR.  */
	size = folded;
    }

  /* Normally, the array-bound will be a constant.  */
  if (TREE_CODE (size) == INTEGER_CST)
    {
      /* The size to use in diagnostics that reflects the constant
	 size used in the source, rather than SIZE massaged above.  */
      tree diagsize = size;

      /* If the original size before conversion to size_t was signed
	 and negative, convert it to ssizetype to restore the sign.  */
      if (!TYPE_UNSIGNED (TREE_TYPE (origsize))
	  && TREE_CODE (size) == INTEGER_CST
	  && tree_int_cst_sign_bit (size))
	{
	  diagsize = fold_convert (ssizetype, size);

	  /* Clear the overflow bit that may have been set as a result
	     of the conversion from the sizetype of the new size to
	     ssizetype.  */
	  TREE_OVERFLOW (diagsize) = false;
	}

      /* Verify that the array has a positive number of elements
	 and issue the appropriate diagnostic if it doesn't.  */
      if (!valid_array_size_p (loc, diagsize, name, (complain & tf_error)))
	{
	  if (!(complain & tf_error))
	    return error_mark_node;
	  size = integer_one_node;
	}
      /* As an extension we allow zero-sized arrays.  */
      else if (integer_zerop (size))
	{
	  if (!(complain & tf_error))
	    /* We must fail if performing argument deduction (as
	       indicated by the state of complain), so that
	       another substitution can be found.  */
	    return error_mark_node;
	  else if (name)
	    pedwarn (loc, OPT_Wpedantic,
		     "ISO C++ forbids zero-size array %qD", name);
	  else
	    pedwarn (loc, OPT_Wpedantic,
		     "ISO C++ forbids zero-size array");
	}
    }
  else if (TREE_CONSTANT (size)
	   /* We don't allow VLAs at non-function scopes, or during
	      tentative template substitution.  */
	   || !at_function_scope_p ()
	   || !(complain & tf_error))
    {
      if (!(complain & tf_error))
	return error_mark_node;
      /* `(int) &fn' is not a valid array bound.  */
      if (name)
	error_at (loc,
		  "size of array %qD is not an integral constant-expression",
		  name);
      else
	error_at (loc, "size of array is not an integral constant-expression");
      size = integer_one_node;
    }
  else if (pedantic && warn_vla != 0)
    {
      if (name)
	pedwarn (name_loc, OPT_Wvla,
		 "ISO C++ forbids variable length array %qD", name);
      else
	pedwarn (input_location, OPT_Wvla,
		 "ISO C++ forbids variable length array");
    }
  else if (warn_vla > 0)
    {
      if (name)
	warning_at (name_loc, OPT_Wvla, 
		    "variable length array %qD is used", name);
      else
	warning (OPT_Wvla, 
                 "variable length array is used");
    }

  if (processing_template_decl && !TREE_CONSTANT (size))
    goto in_template;
  else
    {
      if (!TREE_CONSTANT (size))
	{
	  /* A variable sized array.  Arrange for the SAVE_EXPR on the inside
	     of the MINUS_EXPR, which allows the -1 to get folded with the +1
	     that happens when building TYPE_SIZE.  */
	  size = variable_size (size);
	  stabilize_vla_size (size);
	}

      /* Compute the index of the largest element in the array.  It is
	 one less than the number of elements in the array.  We save
	 and restore PROCESSING_TEMPLATE_DECL so that computations in
	 cp_build_binary_op will be appropriately folded.  */
      {
	processing_template_decl_sentinel s;
	itype = cp_build_binary_op (input_location,
				    MINUS_EXPR,
				    cp_convert (ssizetype, size, complain),
				    cp_convert (ssizetype, integer_one_node,
						complain),
				    complain);
	itype = maybe_constant_value (itype, NULL_TREE, true);
      }

      if (!TREE_CONSTANT (itype))
	{
	  if (sanitize_flags_p (SANITIZE_VLA)
	      && current_function_decl != NULL_TREE)
	    {
	      /* We have to add 1 -- in the ubsan routine we generate
		 LE_EXPR rather than LT_EXPR.  */
	      tree t = fold_build2 (PLUS_EXPR, TREE_TYPE (itype), itype,
				    build_one_cst (TREE_TYPE (itype)));
	      t = ubsan_instrument_vla (input_location, t);
	      finish_expr_stmt (t);
	    }
	}
      /* Make sure that there was no overflow when creating to a signed
	 index type.  (For example, on a 32-bit machine, an array with
	 size 2^32 - 1 is too big.)  */
      else if (TREE_CODE (itype) == INTEGER_CST
	       && TREE_OVERFLOW (itype))
	{
	  if (!(complain & tf_error))
	    return error_mark_node;
	  error ("overflow in array dimension");
	  TREE_OVERFLOW (itype) = 0;
	}
    }

  /* Create and return the appropriate index type.  */
  itype = build_index_type (itype);

  /* If the index type were dependent, we would have returned early, so
     remember that it isn't.  */
  TYPE_DEPENDENT_P (itype) = 0;
  TYPE_DEPENDENT_P_VALID (itype) = 1;
  return itype;
}

tree
compute_array_index_type (tree name, tree size, tsubst_flags_t complain)
{
  return compute_array_index_type_loc (input_location, name, size, complain);
}

/* Returns the scope (if any) in which the entity declared by
   DECLARATOR will be located.  If the entity was declared with an
   unqualified name, NULL_TREE is returned.  */

tree
get_scope_of_declarator (const cp_declarator *declarator)
{
  while (declarator && declarator->kind != cdk_id)
    declarator = declarator->declarator;

  /* If the declarator-id is a SCOPE_REF, the scope in which the
     declaration occurs is the first operand.  */
  if (declarator
      && declarator->u.id.qualifying_scope)
    return declarator->u.id.qualifying_scope;

  /* Otherwise, the declarator is not a qualified name; the entity will
     be declared in the current scope.  */
  return NULL_TREE;
}

/* Returns an ARRAY_TYPE for an array with SIZE elements of the
   indicated TYPE.  If non-NULL, NAME is the NAME of the declaration
   with this type.  */

static tree
create_array_type_for_decl (tree name, tree type, tree size, location_t loc)
{
  tree itype = NULL_TREE;

  /* If things have already gone awry, bail now.  */
  if (type == error_mark_node || size == error_mark_node)
    return error_mark_node;

  /* [dcl.type.class.deduct] prohibits forming an array of placeholder
     for a deduced class type.  */
  if (template_placeholder_p (type))
    {
      if (name)
	error_at (loc, "%qD declared as array of template placeholder "
		  "type %qT", name, type);
      else
	error ("creating array of template placeholder type %qT", type);
      return error_mark_node;
    }

  /* If there are some types which cannot be array elements,
     issue an error-message and return.  */
  switch (TREE_CODE (type))
    {
    case VOID_TYPE:
      if (name)
	error_at (loc, "declaration of %qD as array of void", name);
      else
        error ("creating array of void");
      return error_mark_node;

    case FUNCTION_TYPE:
      if (name)
	error_at (loc, "declaration of %qD as array of functions", name);
      else
        error ("creating array of functions");
      return error_mark_node;

    case REFERENCE_TYPE:
      if (name)
	error_at (loc, "declaration of %qD as array of references", name);
      else
        error ("creating array of references");
      return error_mark_node;

    case METHOD_TYPE:
      if (name)
	error_at (loc, "declaration of %qD as array of function members",
		  name);
      else
        error ("creating array of function members");
      return error_mark_node;

    default:
      break;
    }

  if (!verify_type_context (name ? loc : input_location,
			    TCTX_ARRAY_ELEMENT, type))
    return error_mark_node;

  /* [dcl.array]

     The constant expressions that specify the bounds of the arrays
     can be omitted only for the first member of the sequence.  */
  if (TREE_CODE (type) == ARRAY_TYPE && !TYPE_DOMAIN (type))
    {
      if (name)
	error_at (loc, "declaration of %qD as multidimensional array must "
		  "have bounds for all dimensions except the first",
		  name);
      else
	error ("multidimensional array must have bounds for all "
	       "dimensions except the first");

      return error_mark_node;
    }

  /* Figure out the index type for the array.  */
  if (size)
    {
      itype = compute_array_index_type_loc (loc, name, size,
					    tf_warning_or_error);
      if (type_uses_auto (type)
	  && variably_modified_type_p (itype, /*fn=*/NULL_TREE))
	{
	  sorry_at (loc, "variable-length array of %<auto%>");
	  return error_mark_node;
	}
    }

  return build_cplus_array_type (type, itype);
}

/* Returns the smallest location that is not UNKNOWN_LOCATION.  */

static location_t
min_location (location_t loca, location_t locb)
{
  if (loca == UNKNOWN_LOCATION
      || (locb != UNKNOWN_LOCATION
	  && linemap_location_before_p (line_table, locb, loca)))
    return locb;
  return loca;
}

/* Returns the smallest location != UNKNOWN_LOCATION among the
   three stored in LOCATIONS[ds_const], LOCATIONS[ds_volatile],
   and LOCATIONS[ds_restrict].  */

static location_t
smallest_type_quals_location (int type_quals, const location_t* locations)
{
  location_t loc = UNKNOWN_LOCATION;

  if (type_quals & TYPE_QUAL_CONST)
    loc = locations[ds_const];

  if (type_quals & TYPE_QUAL_VOLATILE)
    loc = min_location (loc, locations[ds_volatile]);

  if (type_quals & TYPE_QUAL_RESTRICT)
    loc = min_location (loc, locations[ds_restrict]);

  return loc;
}

/* Returns the smallest among the latter and locations[ds_type_spec].  */

static location_t
smallest_type_location (int type_quals, const location_t* locations)
{
  location_t loc = smallest_type_quals_location (type_quals, locations);
  return min_location (loc, locations[ds_type_spec]);
}

static location_t
smallest_type_location (const cp_decl_specifier_seq *declspecs)
{
  int type_quals = get_type_quals (declspecs);
  return smallest_type_location (type_quals, declspecs->locations);
}

/* Check that it's OK to declare a function with the indicated TYPE
   and TYPE_QUALS.  SFK indicates the kind of special function (if any)
   that this function is.  OPTYPE is the type given in a conversion
   operator declaration, or the class type for a constructor/destructor.
   Returns the actual return type of the function; that may be different
   than TYPE if an error occurs, or for certain special functions.  */

static tree
check_special_function_return_type (special_function_kind sfk,
				    tree type,
				    tree optype,
				    int type_quals,
				    const location_t* locations)
{
  switch (sfk)
    {
    case sfk_constructor:
      if (type)
	error_at (smallest_type_location (type_quals, locations),
		  "return type specification for constructor invalid");
      else if (type_quals != TYPE_UNQUALIFIED)
	error_at (smallest_type_quals_location (type_quals, locations),
		  "qualifiers are not allowed on constructor declaration");

      if (targetm.cxx.cdtor_returns_this ())
	type = build_pointer_type (optype);
      else
	type = void_type_node;
      break;

    case sfk_destructor:
      if (type)
	error_at (smallest_type_location (type_quals, locations),
		  "return type specification for destructor invalid");
      else if (type_quals != TYPE_UNQUALIFIED)
	error_at (smallest_type_quals_location (type_quals, locations),
		  "qualifiers are not allowed on destructor declaration");

      /* We can't use the proper return type here because we run into
	 problems with ambiguous bases and covariant returns.  */
      if (targetm.cxx.cdtor_returns_this ())
	type = build_pointer_type (void_type_node);
      else
	type = void_type_node;
      break;

    case sfk_conversion:
      if (type)
	error_at (smallest_type_location (type_quals, locations),
		  "return type specified for %<operator %T%>", optype);
      else if (type_quals != TYPE_UNQUALIFIED)
	error_at (smallest_type_quals_location (type_quals, locations),
		  "qualifiers are not allowed on declaration of "
		  "%<operator %T%>", optype);

      type = optype;
      break;

    case sfk_deduction_guide:
      if (type)
	error_at (smallest_type_location (type_quals, locations),
		  "return type specified for deduction guide");
      else if (type_quals != TYPE_UNQUALIFIED)
	error_at (smallest_type_quals_location (type_quals, locations),
		  "qualifiers are not allowed on declaration of "
		  "deduction guide");
      if (TREE_CODE (optype) == TEMPLATE_TEMPLATE_PARM)
	{
	  error ("template template parameter %qT in declaration of "
		 "deduction guide", optype);
	  type = error_mark_node;
	}
      else
	type = make_template_placeholder (CLASSTYPE_TI_TEMPLATE (optype));
      for (int i = 0; i < ds_last; ++i)
	if (i != ds_explicit && locations[i])
	  error_at (locations[i],
		    "%<decl-specifier%> in declaration of deduction guide");
      break;

    default:
      gcc_unreachable ();
    }

  return type;
}

/* A variable or data member (whose unqualified name is IDENTIFIER)
   has been declared with the indicated TYPE.  If the TYPE is not
   acceptable, issue an error message and return a type to use for
   error-recovery purposes.  */

tree
check_var_type (tree identifier, tree type, location_t loc)
{
  if (VOID_TYPE_P (type))
    {
      if (!identifier)
	error_at (loc, "unnamed variable or field declared void");
      else if (identifier_p (identifier))
	{
	  gcc_assert (!IDENTIFIER_ANY_OP_P (identifier));
	  error_at (loc, "variable or field %qE declared void",
		    identifier);
	}
      else
	error_at (loc, "variable or field declared void");
      type = error_mark_node;
    }

  return type;
}

/* Handle declaring DECL as an inline variable.  */

static void
mark_inline_variable (tree decl, location_t loc)
{
  bool inlinep = true;
  if (! toplevel_bindings_p ())
    {
      error_at (loc, "%<inline%> specifier invalid for variable "
		"%qD declared at block scope", decl);
      inlinep = false;
    }
  else if (cxx_dialect < cxx17)
    pedwarn (loc, OPT_Wc__17_extensions, "inline variables are only available "
	     "with %<-std=c++17%> or %<-std=gnu++17%>");
  if (inlinep)
    {
      retrofit_lang_decl (decl);
      SET_DECL_VAR_DECLARED_INLINE_P (decl);
    }
}


/* Assign a typedef-given name to a class or enumeration type declared
   as anonymous at first.  This was split out of grokdeclarator
   because it is also used in libcc1.  */

void
name_unnamed_type (tree type, tree decl)
{
  gcc_assert (TYPE_UNNAMED_P (type));

  /* Replace the anonymous decl with the real decl.  Be careful not to
     rename other typedefs (such as the self-reference) of type.  */
  tree orig = TYPE_NAME (type);
  for (tree t = TYPE_MAIN_VARIANT (type); t; t = TYPE_NEXT_VARIANT (t))
    if (TYPE_NAME (t) == orig)
      TYPE_NAME (t) = decl;

  /* If this is a typedef within a template class, the nested
     type is a (non-primary) template.  The name for the
     template needs updating as well.  */
  if (TYPE_LANG_SPECIFIC (type) && CLASSTYPE_TEMPLATE_INFO (type))
    DECL_NAME (CLASSTYPE_TI_TEMPLATE (type)) = DECL_NAME (decl);

  /* Adjust linkage now that we aren't unnamed anymore.  */
  reset_type_linkage (type);

  /* FIXME remangle member functions; member functions of a
     type with external linkage have external linkage.  */

  /* Check that our job is done, and that it would fail if we
     attempted to do it again.  */
  gcc_assert (!TYPE_UNNAMED_P (type));
}

/* Check that decltype(auto) was well-formed: only plain decltype(auto)
   is allowed.  TYPE might contain a decltype(auto).  Returns true if
   there was a problem, false otherwise.  */

static bool
check_decltype_auto (location_t loc, tree type)
{
  if (tree a = type_uses_auto (type))
    {
      if (AUTO_IS_DECLTYPE (a))
	{
	  if (a != type)
	    {
	      error_at (loc, "%qT as type rather than plain "
			"%<decltype(auto)%>", type);
	      return true;
	    }
	  else if (TYPE_QUALS (type) != TYPE_UNQUALIFIED)
	    {
	      error_at (loc, "%<decltype(auto)%> cannot be cv-qualified");
	      return true;
	    }
	}
    }
  return false;
}

/* Given declspecs and a declarator (abstract or otherwise), determine
   the name and type of the object declared and construct a DECL node
   for it.

   DECLSPECS points to the representation of declaration-specifier
   sequence that precedes declarator.

   DECL_CONTEXT says which syntactic context this declaration is in:
     NORMAL for most contexts.  Make a VAR_DECL or FUNCTION_DECL or TYPE_DECL.
     FUNCDEF for a function definition.  Like NORMAL but a few different
      error messages in each case.  Return value may be zero meaning
      this definition is too screwy to try to parse.
     MEMFUNCDEF for a function definition.  Like FUNCDEF but prepares to
      handle member functions (which have FIELD context).
      Return value may be zero meaning this definition is too screwy to
      try to parse.
     PARM for a parameter declaration (either within a function prototype
      or before a function body).  Make a PARM_DECL, or return void_type_node.
     TPARM for a template parameter declaration.
     CATCHPARM for a parameter declaration before a catch clause.
     TYPENAME if for a typename (in a cast or sizeof).
      Don't make a DECL node; just return the ..._TYPE node.
     FIELD for a struct or union field; make a FIELD_DECL.
     BITFIELD for a field with specified width.

   INITIALIZED is as for start_decl.

   ATTRLIST is a pointer to the list of attributes, which may be NULL
   if there are none; *ATTRLIST may be modified if attributes from inside
   the declarator should be applied to the declaration.

   When this function is called, scoping variables (such as
   CURRENT_CLASS_TYPE) should reflect the scope in which the
   declaration occurs, not the scope in which the new declaration will
   be placed.  For example, on:

     void S::f() { ... }

   when grokdeclarator is called for `S::f', the CURRENT_CLASS_TYPE
   should not be `S'.

   Returns a DECL (if a declarator is present), a TYPE (if there is no
   declarator, in cases like "struct S;"), or the ERROR_MARK_NODE if an
   error occurs. */

tree
grokdeclarator (const cp_declarator *declarator,
		cp_decl_specifier_seq *declspecs,
		enum decl_context decl_context,
		int initialized,
		tree* attrlist)
{
  tree type = NULL_TREE;
  int longlong = 0;
  int explicit_intN = 0;
  int int_n_alt = 0;
  int virtualp, explicitp, friendp, inlinep, staticp;
  int explicit_int = 0;
  int explicit_char = 0;
  int defaulted_int = 0;

  tree typedef_decl = NULL_TREE;
  const char *name = NULL;
  tree typedef_type = NULL_TREE;
  /* True if this declarator is a function definition.  */
  bool funcdef_flag = false;
  cp_declarator_kind innermost_code = cdk_error;
  int bitfield = 0;
#if 0
  /* See the code below that used this.  */
  tree decl_attr = NULL_TREE;
#endif

  /* Keep track of what sort of function is being processed
     so that we can warn about default return values, or explicit
     return values which do not match prescribed defaults.  */
  special_function_kind sfk = sfk_none;

  tree dname = NULL_TREE;
  tree ctor_return_type = NULL_TREE;
  enum overload_flags flags = NO_SPECIAL;
  /* cv-qualifiers that apply to the declarator, for a declaration of
     a member function.  */
  cp_cv_quals memfn_quals = TYPE_UNQUALIFIED;
  /* virt-specifiers that apply to the declarator, for a declaration of
     a member function.  */
  cp_virt_specifiers virt_specifiers = VIRT_SPEC_UNSPECIFIED;
  /* ref-qualifier that applies to the declarator, for a declaration of
     a member function.  */
  cp_ref_qualifier rqual = REF_QUAL_NONE;
  /* cv-qualifiers that apply to the type specified by the DECLSPECS.  */
  int type_quals = get_type_quals (declspecs);
  tree raises = NULL_TREE;
  int template_count = 0;
  tree returned_attrs = NULL_TREE;
  tree parms = NULL_TREE;
  const cp_declarator *id_declarator;
  /* The unqualified name of the declarator; either an
     IDENTIFIER_NODE, BIT_NOT_EXPR, or TEMPLATE_ID_EXPR.  */
  tree unqualified_id;
  /* The class type, if any, in which this entity is located,
     or NULL_TREE if none.  Note that this value may be different from
     the current class type; for example if an attempt is made to declare
     "A::f" inside "B", this value will be "A".  */
  tree ctype = current_class_type;
  /* The NAMESPACE_DECL for the namespace in which this entity is
     located.  If an unqualified name is used to declare the entity,
     this value will be NULL_TREE, even if the entity is located at
     namespace scope.  */
  tree in_namespace = NULL_TREE;
  cp_storage_class storage_class;
  bool unsigned_p, signed_p, short_p, long_p, thread_p;
  bool type_was_error_mark_node = false;
  bool parameter_pack_p = declarator ? declarator->parameter_pack_p : false;
  bool template_type_arg = false;
  bool template_parm_flag = false;
  bool typedef_p = decl_spec_seq_has_spec_p (declspecs, ds_typedef);
  bool constexpr_p = decl_spec_seq_has_spec_p (declspecs, ds_constexpr);
  bool constinit_p = decl_spec_seq_has_spec_p (declspecs, ds_constinit);
  bool consteval_p = decl_spec_seq_has_spec_p (declspecs, ds_consteval);
  bool late_return_type_p = false;
  bool array_parameter_p = false;
  tree reqs = NULL_TREE;

  signed_p = decl_spec_seq_has_spec_p (declspecs, ds_signed);
  unsigned_p = decl_spec_seq_has_spec_p (declspecs, ds_unsigned);
  short_p = decl_spec_seq_has_spec_p (declspecs, ds_short);
  long_p = decl_spec_seq_has_spec_p (declspecs, ds_long);
  longlong = decl_spec_seq_has_spec_p (declspecs, ds_long_long);
  explicit_intN = declspecs->explicit_intN_p;
  int_n_alt = declspecs->int_n_alt;
  thread_p = decl_spec_seq_has_spec_p (declspecs, ds_thread);

  // Was concept_p specified? Note that ds_concept
  // implies ds_constexpr!
  bool concept_p = decl_spec_seq_has_spec_p (declspecs, ds_concept);
  if (concept_p)
    constexpr_p = true;

  if (decl_context == FUNCDEF)
    funcdef_flag = true, decl_context = NORMAL;
  else if (decl_context == MEMFUNCDEF)
    funcdef_flag = true, decl_context = FIELD;
  else if (decl_context == BITFIELD)
    bitfield = 1, decl_context = FIELD;
  else if (decl_context == TEMPLATE_TYPE_ARG)
    template_type_arg = true, decl_context = TYPENAME;
  else if (decl_context == TPARM)
    template_parm_flag = true, decl_context = PARM;

  if (initialized == SD_DEFAULTED || initialized == SD_DELETED)
    funcdef_flag = true;

  location_t typespec_loc = loc_or_input_loc (smallest_type_location
					      (type_quals,
					       declspecs->locations));
  location_t id_loc;
  location_t init_loc;
  if (declarator)
    {
      id_loc = loc_or_input_loc (declarator->id_loc);
      init_loc = loc_or_input_loc (declarator->init_loc);
    }
  else
    init_loc = id_loc = input_location;

  /* Look inside a declarator for the name being declared
     and get it as a string, for an error message.  */
  for (id_declarator = declarator;
       id_declarator;
       id_declarator = id_declarator->declarator)
    {
      if (id_declarator->kind != cdk_id)
	innermost_code = id_declarator->kind;

      switch (id_declarator->kind)
	{
	case cdk_function:
	  if (id_declarator->declarator
	      && id_declarator->declarator->kind == cdk_id)
	    {
	      sfk = id_declarator->declarator->u.id.sfk;
	      if (sfk == sfk_destructor)
		flags = DTOR_FLAG;
	    }
	  break;

	case cdk_id:
	  {
	    tree qualifying_scope = id_declarator->u.id.qualifying_scope;
	    tree decl = id_declarator->u.id.unqualified_name;
	    if (!decl)
	      break;
	    if (qualifying_scope)
	      {
		if (check_for_bare_parameter_packs (qualifying_scope,
						    id_declarator->id_loc))
		  return error_mark_node;
		if (at_function_scope_p ())
		  {
		    /* [dcl.meaning] 

		       A declarator-id shall not be qualified except
		       for ... 

		       None of the cases are permitted in block
		       scope.  */
		    if (qualifying_scope == global_namespace)
		      error ("invalid use of qualified-name %<::%D%>",
			     decl);
		    else if (TYPE_P (qualifying_scope))
		      error ("invalid use of qualified-name %<%T::%D%>",
			     qualifying_scope, decl);
		    else 
		      error ("invalid use of qualified-name %<%D::%D%>",
			     qualifying_scope, decl);
		    return error_mark_node;
		  }
		else if (TYPE_P (qualifying_scope))
		  {
		    ctype = qualifying_scope;
		    if (!MAYBE_CLASS_TYPE_P (ctype))
		      {
			error_at (id_declarator->id_loc,
				  "%q#T is not a class or namespace", ctype);
			ctype = NULL_TREE;
		      }
		    else if (innermost_code != cdk_function
			     && current_class_type
			     && !uniquely_derived_from_p (ctype,
							  current_class_type))
		      {
			error_at (id_declarator->id_loc,
				  "invalid use of qualified-name %<%T::%D%>",
				  qualifying_scope, decl);
			return error_mark_node;
		      }
		  }
		else if (TREE_CODE (qualifying_scope) == NAMESPACE_DECL)
		  in_namespace = qualifying_scope;
	      }
	    switch (TREE_CODE (decl))
	      {
	      case BIT_NOT_EXPR:
		{
		  if (innermost_code != cdk_function)
		    {
		      error_at (EXPR_LOCATION (decl),
				"declaration of %qE as non-function", decl);
		      return error_mark_node;
		    }
		  else if (!qualifying_scope
			   && !(current_class_type && at_class_scope_p ()))
		    {
		      error_at (EXPR_LOCATION (decl),
				"declaration of %qE as non-member", decl);
		      return error_mark_node;
		    }

		  tree type = TREE_OPERAND (decl, 0);
		  if (TYPE_P (type))
		    type = constructor_name (type);
		  name = identifier_to_locale (IDENTIFIER_POINTER (type));
		  dname = decl;
		}
		break;

	      case TEMPLATE_ID_EXPR:
		{
		  tree fns = TREE_OPERAND (decl, 0);

		  dname = fns;
		  if (!identifier_p (dname))
		    dname = OVL_NAME (dname);
		}
		/* Fall through.  */

	      case IDENTIFIER_NODE:
		if (identifier_p (decl))
		  dname = decl;

		if (IDENTIFIER_KEYWORD_P (dname))
		  {
		    error ("declarator-id missing; using reserved word %qD",
			   dname);
		    name = identifier_to_locale (IDENTIFIER_POINTER (dname));
		  }
		else if (!IDENTIFIER_CONV_OP_P (dname))
		  name = identifier_to_locale (IDENTIFIER_POINTER (dname));
		else
		  {
		    gcc_assert (flags == NO_SPECIAL);
		    flags = TYPENAME_FLAG;
		    sfk = sfk_conversion;
		    tree glob = get_global_binding (dname);
		    if (glob && TREE_CODE (glob) == TYPE_DECL)
		      name = identifier_to_locale (IDENTIFIER_POINTER (dname));
		    else
		      name = "<invalid operator>";
		  }
		break;

	      default:
		gcc_unreachable ();
	      }
	    break;
	  }

	case cdk_array:
	case cdk_pointer:
	case cdk_reference:
	case cdk_ptrmem:
	  break;

	case cdk_decomp:
	  name = "structured binding";
	  break;

	case cdk_error:
	  return error_mark_node;

	default:
	  gcc_unreachable ();
	}
      if (id_declarator->kind == cdk_id)
	break;
    }

  /* [dcl.fct.edf]

     The declarator in a function-definition shall have the form
     D1 ( parameter-declaration-clause) ...  */
  if (funcdef_flag && innermost_code != cdk_function)
    {
      error_at (id_loc, "function definition does not declare parameters");
      return error_mark_node;
    }

  if (flags == TYPENAME_FLAG
      && innermost_code != cdk_function
      && ! (ctype && !declspecs->any_specifiers_p))
    {
      error_at (id_loc, "declaration of %qD as non-function", dname);
      return error_mark_node;
    }

  if (dname && identifier_p (dname))
    {
      if (UDLIT_OPER_P (dname)
	  && innermost_code != cdk_function)
	{
	  error_at (id_loc, "declaration of %qD as non-function", dname);
	  return error_mark_node;
	}

      if (IDENTIFIER_ANY_OP_P (dname))
	{
	  if (typedef_p)
	    {
	      error_at (id_loc, "declaration of %qD as %<typedef%>", dname);
	      return error_mark_node;
	    }
	  else if (decl_context == PARM || decl_context == CATCHPARM)
	    {
	      error_at (id_loc, "declaration of %qD as parameter", dname);
	      return error_mark_node;
	    }
	}
    }

  /* Anything declared one level down from the top level
     must be one of the parameters of a function
     (because the body is at least two levels down).  */

  /* This heuristic cannot be applied to C++ nodes! Fixed, however,
     by not allowing C++ class definitions to specify their parameters
     with xdecls (must be spec.d in the parmlist).

     Since we now wait to push a class scope until we are sure that
     we are in a legitimate method context, we must set oldcname
     explicitly (since current_class_name is not yet alive).

     We also want to avoid calling this a PARM if it is in a namespace.  */

  if (decl_context == NORMAL && !toplevel_bindings_p ())
    {
      cp_binding_level *b = current_binding_level;
      current_binding_level = b->level_chain;
      if (current_binding_level != 0 && toplevel_bindings_p ())
	decl_context = PARM;
      current_binding_level = b;
    }

  if (name == NULL)
    name = decl_context == PARM ? "parameter" : "type name";

  if (consteval_p && constexpr_p)
    {
      error_at (declspecs->locations[ds_consteval],
		"both %qs and %qs specified", "constexpr", "consteval");
      return error_mark_node;
    }

  if (concept_p && typedef_p)
    {
      error_at (declspecs->locations[ds_concept],
		"%qs cannot appear in a typedef declaration", "concept");
      return error_mark_node;
    }

  if (constexpr_p && typedef_p)
    {
      error_at (declspecs->locations[ds_constexpr],
		"%qs cannot appear in a typedef declaration", "constexpr");
      return error_mark_node;
    }

  if (consteval_p && typedef_p)
    {
      error_at (declspecs->locations[ds_consteval],
		"%qs cannot appear in a typedef declaration", "consteval");
      return error_mark_node;
    }

  if (constinit_p && typedef_p)
    {
      error_at (declspecs->locations[ds_constinit],
		"%qs cannot appear in a typedef declaration", "constinit");
      return error_mark_node;
    }

  /* [dcl.spec]/2 "At most one of the constexpr, consteval, and constinit
     keywords shall appear in a decl-specifier-seq."  */
  if (constinit_p && constexpr_p)
    {
      gcc_rich_location richloc (declspecs->locations[ds_constinit]);
      richloc.add_range (declspecs->locations[ds_constexpr]);
      error_at (&richloc,
		"can use at most one of the %<constinit%> and %<constexpr%> "
		"specifiers");
      return error_mark_node;
    }

  /* If there were multiple types specified in the decl-specifier-seq,
     issue an error message.  */
  if (declspecs->multiple_types_p)
    {
      error_at (typespec_loc,
		"two or more data types in declaration of %qs", name);
      return error_mark_node;
    }

  if (declspecs->conflicting_specifiers_p)
    {
      error_at (min_location (declspecs->locations[ds_typedef],
			      declspecs->locations[ds_storage_class]),
		"conflicting specifiers in declaration of %qs", name);
      return error_mark_node;
    }

  /* Extract the basic type from the decl-specifier-seq.  */
  type = declspecs->type;
  if (type == error_mark_node)
    {
      type = NULL_TREE;
      type_was_error_mark_node = true;
    }

  /* Ignore erroneous attributes.  */
  if (attrlist && *attrlist == error_mark_node)
    *attrlist = NULL_TREE;

  /* An object declared as __attribute__((unavailable)) suppresses
     any reports of being declared with unavailable or deprecated
     items.  An object declared as __attribute__((deprecated))
     suppresses warnings of uses of other deprecated items.  */
  auto ds = make_temp_override (deprecated_state);
  if (attrlist && lookup_attribute ("unavailable", *attrlist))
    deprecated_state = UNAVAILABLE_DEPRECATED_SUPPRESS;
  else if (attrlist && lookup_attribute ("deprecated", *attrlist))
    deprecated_state = DEPRECATED_SUPPRESS;

  cp_handle_deprecated_or_unavailable (type);
  if (type && TREE_CODE (type) == TYPE_DECL)
    {
      cp_warn_deprecated_use_scopes (CP_DECL_CONTEXT (type));
      typedef_decl = type;
      type = TREE_TYPE (typedef_decl);
      if (DECL_ARTIFICIAL (typedef_decl))
	cp_handle_deprecated_or_unavailable (type);
    }
  /* No type at all: default to `int', and set DEFAULTED_INT
     because it was not a user-defined typedef.  */
  if (type == NULL_TREE)
    {
      if (signed_p || unsigned_p || long_p || short_p)
	{
	  /* These imply 'int'.  */
	  type = integer_type_node;
	  defaulted_int = 1;
	}
      /* If we just have "complex", it is equivalent to "complex double".  */
      else if (!longlong && !explicit_intN
	       && decl_spec_seq_has_spec_p (declspecs, ds_complex))
	{
	  type = double_type_node;
	  pedwarn (declspecs->locations[ds_complex], OPT_Wpedantic,
		   "ISO C++ does not support plain %<complex%> meaning "
		   "%<double complex%>");
	}
    }
  /* Gather flags.  */
  explicit_int = declspecs->explicit_int_p;
  explicit_char = declspecs->explicit_char_p;

#if 0
  /* See the code below that used this.  */
  if (typedef_decl)
    decl_attr = DECL_ATTRIBUTES (typedef_decl);
#endif
  typedef_type = type;

  if (sfk == sfk_conversion || sfk == sfk_deduction_guide)
    ctor_return_type = TREE_TYPE (dname);
  else
    ctor_return_type = ctype;

  if (sfk != sfk_none)
    {
      type = check_special_function_return_type (sfk, type,
						 ctor_return_type,
						 type_quals,
						 declspecs->locations);
      type_quals = TYPE_UNQUALIFIED;
    }
  else if (type == NULL_TREE)
    {
      int is_main;

      explicit_int = -1;

      /* We handle `main' specially here, because 'main () { }' is so
	 common.  With no options, it is allowed.  With -Wreturn-type,
	 it is a warning.  It is only an error with -pedantic-errors.  */
      is_main = (funcdef_flag
		 && dname && identifier_p (dname)
		 && MAIN_NAME_P (dname)
		 && ctype == NULL_TREE
		 && in_namespace == NULL_TREE
		 && current_namespace == global_namespace);

      if (type_was_error_mark_node)
	/* We've already issued an error, don't complain more.  */;
      else if (in_system_header_at (id_loc) || flag_ms_extensions)
	/* Allow it, sigh.  */;
      else if (! is_main)
	permerror (id_loc, "ISO C++ forbids declaration of %qs with no type",
		   name);
      else if (pedantic)
	pedwarn (id_loc, OPT_Wpedantic,
		 "ISO C++ forbids declaration of %qs with no type", name);
      else
	warning_at (id_loc, OPT_Wreturn_type,
		    "ISO C++ forbids declaration of %qs with no type", name);

      if (type_was_error_mark_node && template_parm_flag)
	/* FIXME we should be able to propagate the error_mark_node as is
	   for other contexts too.  */
	type = error_mark_node;
      else
	type = integer_type_node;
    }

  ctype = NULL_TREE;

  if (explicit_intN)
    {
      if (! int_n_enabled_p[declspecs->int_n_idx])
	{
	  error_at (declspecs->locations[ds_type_spec],
		    "%<__int%d%> is not supported by this target",
		    int_n_data[declspecs->int_n_idx].bitsize);
	  explicit_intN = false;
	}
      /* Don't pedwarn if the alternate "__intN__" form has been used instead
	 of "__intN".  */
      else if (!int_n_alt && pedantic)
	pedwarn (declspecs->locations[ds_type_spec], OPT_Wpedantic,
		 "ISO C++ does not support %<__int%d%> for %qs",
		 int_n_data[declspecs->int_n_idx].bitsize, name);
    }

  /* Now process the modifiers that were specified
     and check for invalid combinations.  */

  /* Long double is a special combination.  */
  if (long_p && !longlong && TYPE_MAIN_VARIANT (type) == double_type_node)
    {
      long_p = false;
      type = cp_build_qualified_type (long_double_type_node,
				      cp_type_quals (type));
    }

  /* Check all other uses of type modifiers.  */

  if (unsigned_p || signed_p || long_p || short_p)
    {
      location_t loc;
      const char *key;
      if (unsigned_p)
	{
	  key = "unsigned";
	  loc = declspecs->locations[ds_unsigned];
	}
      else if (signed_p)
	{
	  key = "signed";
	  loc = declspecs->locations[ds_signed];
	}
      else if (longlong)
	{
	  key = "long long";
	  loc = declspecs->locations[ds_long_long];
	}
      else if (long_p)
	{
	  key = "long";
	  loc = declspecs->locations[ds_long];
	}
      else /* if (short_p) */
	{
	  key = "short";
	  loc = declspecs->locations[ds_short];
	}

      int ok = 0;

      if (signed_p && unsigned_p)
	{
	  gcc_rich_location richloc (declspecs->locations[ds_signed]);
	  richloc.add_range (declspecs->locations[ds_unsigned]);
	  error_at (&richloc,
		    "%<signed%> and %<unsigned%> specified together");
	}
      else if (long_p && short_p)
	{
	  gcc_rich_location richloc (declspecs->locations[ds_long]);
	  richloc.add_range (declspecs->locations[ds_short]);
	  error_at (&richloc, "%<long%> and %<short%> specified together");
	}
      else if (TREE_CODE (type) != INTEGER_TYPE
	       || type == char8_type_node
	       || type == char16_type_node
	       || type == char32_type_node
	       || ((long_p || short_p)
		   && (explicit_char || explicit_intN)))
	error_at (loc, "%qs specified with %qT", key, type);
      else if (!explicit_int && !defaulted_int
	       && !explicit_char && !explicit_intN)
	{
	  if (typedef_decl)
	    {
	      pedwarn (loc, OPT_Wpedantic,
		       "%qs specified with typedef-name %qD",
		       key, typedef_decl);
	      ok = !flag_pedantic_errors;
	      /* PR108099: __int128_t comes from c_common_nodes_and_builtins,
		 and is not built as a typedef.  */
	      if (is_typedef_decl (typedef_decl))
		type = DECL_ORIGINAL_TYPE (typedef_decl);
	    }
	  else if (declspecs->decltype_p)
	    error_at (loc, "%qs specified with %<decltype%>", key);
	  else
	    error_at (loc, "%qs specified with %<typeof%>", key);
	}
      else
	ok = 1;

      /* Discard the type modifiers if they are invalid.  */
      if (! ok)
	{
	  unsigned_p = false;
	  signed_p = false;
	  long_p = false;
	  short_p = false;
	  longlong = 0;
	}
    }

  /* Decide whether an integer type is signed or not.
     Optionally treat bitfields as signed by default.  */
  if (unsigned_p
      /* [class.bit]

	 It is implementation-defined whether a plain (neither
	 explicitly signed or unsigned) char, short, int, or long
	 bit-field is signed or unsigned.

	 Naturally, we extend this to long long as well.  Note that
	 this does not include wchar_t.  */
      || (bitfield && !flag_signed_bitfields
	  && !signed_p
	  /* A typedef for plain `int' without `signed' can be
	     controlled just like plain `int', but a typedef for
	     `signed int' cannot be so controlled.  */
	  && !(typedef_decl
	       && C_TYPEDEF_EXPLICITLY_SIGNED (typedef_decl))
	  && TREE_CODE (type) == INTEGER_TYPE
	  && !same_type_p (TYPE_MAIN_VARIANT (type), wchar_type_node)))
    {
      if (explicit_intN)
	type = int_n_trees[declspecs->int_n_idx].unsigned_type;
      else if (longlong)
	type = long_long_unsigned_type_node;
      else if (long_p)
	type = long_unsigned_type_node;
      else if (short_p)
	type = short_unsigned_type_node;
      else if (type == char_type_node)
	type = unsigned_char_type_node;
      else if (typedef_decl)
	type = c_common_unsigned_type (type);
      else
	type = unsigned_type_node;
    }
  else if (signed_p && type == char_type_node)
    type = signed_char_type_node;
  else if (explicit_intN)
    type = int_n_trees[declspecs->int_n_idx].signed_type;
  else if (longlong)
    type = long_long_integer_type_node;
  else if (long_p)
    type = long_integer_type_node;
  else if (short_p)
    type = short_integer_type_node;
  else if (signed_p && typedef_decl)
    type = c_common_signed_type (type);

  if (decl_spec_seq_has_spec_p (declspecs, ds_complex))
    {
      if (TREE_CODE (type) != INTEGER_TYPE && TREE_CODE (type) != REAL_TYPE)
	error_at (declspecs->locations[ds_complex],
		  "complex invalid for %qs", name);
      /* If a modifier is specified, the resulting complex is the complex
	 form of TYPE.  E.g, "complex short" is "complex short int".  */
      else if (type == integer_type_node)
	type = complex_integer_type_node;
      else if (type == float_type_node)
	type = complex_float_type_node;
      else if (type == double_type_node)
	type = complex_double_type_node;
      else if (type == long_double_type_node)
	type = complex_long_double_type_node;
      else
	type = build_complex_type (type);
    }

  /* If we're using the injected-class-name to form a compound type or a
     declaration, replace it with the underlying class so we don't get
     redundant typedefs in the debug output.  But if we are returning the
     type unchanged, leave it alone so that it's available to
     maybe_get_template_decl_from_type_decl.  */
  if (CLASS_TYPE_P (type)
      && DECL_SELF_REFERENCE_P (TYPE_NAME (type))
      && type == TREE_TYPE (TYPE_NAME (type))
      && (declarator || type_quals))
    type = DECL_ORIGINAL_TYPE (TYPE_NAME (type));

  type_quals |= cp_type_quals (type);
  type = cp_build_qualified_type_real
    (type, type_quals, ((((typedef_decl && !DECL_ARTIFICIAL (typedef_decl))
			  || declspecs->decltype_p)
			 ? tf_ignore_bad_quals : 0) | tf_warning_or_error));
  /* We might have ignored or rejected some of the qualifiers.  */
  type_quals = cp_type_quals (type);

  if (cxx_dialect >= cxx17 && type && is_auto (type)
      && innermost_code != cdk_function
      && id_declarator && declarator != id_declarator)
    if (tree tmpl = CLASS_PLACEHOLDER_TEMPLATE (type))
    {
      error_at (typespec_loc, "template placeholder type %qT must be followed "
		"by a simple declarator-id", type);
      inform (DECL_SOURCE_LOCATION (tmpl), "%qD declared here", tmpl);
      type = error_mark_node;
    }

  staticp = 0;
  inlinep = decl_spec_seq_has_spec_p (declspecs, ds_inline);
  virtualp =  decl_spec_seq_has_spec_p (declspecs, ds_virtual);
  explicitp = decl_spec_seq_has_spec_p (declspecs, ds_explicit);

  storage_class = declspecs->storage_class;
  if (storage_class == sc_static)
    staticp = 1 + (decl_context == FIELD);
  else if (decl_context == FIELD && sfk == sfk_deduction_guide)
    /* Treat class-scope deduction guides as static member functions
       so that they get a FUNCTION_TYPE instead of a METHOD_TYPE.  */
    staticp = 2;

  if (virtualp)
    {
      if (staticp == 2)
	{
	  gcc_rich_location richloc (declspecs->locations[ds_virtual]);
	  richloc.add_range (declspecs->locations[ds_storage_class]);
	  error_at (&richloc, "member %qD cannot be declared both %<virtual%> "
		    "and %<static%>", dname);
	  storage_class = sc_none;
	  staticp = 0;
	}
      if (constexpr_p && pedantic && cxx_dialect < cxx20)
	{
	  gcc_rich_location richloc (declspecs->locations[ds_virtual]);
	  richloc.add_range (declspecs->locations[ds_constexpr]);
	  pedwarn (&richloc, OPT_Wc__20_extensions, "member %qD can be "
		   "declared both %<virtual%> and %<constexpr%> only in "
		   "%<-std=c++20%> or %<-std=gnu++20%>", dname);
	}
    }
  friendp = decl_spec_seq_has_spec_p (declspecs, ds_friend);

  /* Issue errors about use of storage classes for parameters.  */
  if (decl_context == PARM)
    {
      if (typedef_p)
	{
	  error_at (declspecs->locations[ds_typedef],
		    "typedef declaration invalid in parameter declaration");
	  return error_mark_node;
	}
      else if (template_parm_flag && storage_class != sc_none)
	{
	  error_at (min_location (declspecs->locations[ds_thread],
				  declspecs->locations[ds_storage_class]),
		    "storage class specified for template parameter %qs",
		    name);
	  return error_mark_node;
	}
      else if (storage_class == sc_static
	       || storage_class == sc_extern
	       || thread_p)
	{
	  error_at (min_location (declspecs->locations[ds_thread],
				  declspecs->locations[ds_storage_class]),
		    "storage class specified for parameter %qs", name);
	  return error_mark_node;
	}

      /* Function parameters cannot be concept. */
      if (concept_p)
	{
	  error_at (declspecs->locations[ds_concept],
		    "a parameter cannot be declared %qs", "concept");
	  concept_p = 0;
	  constexpr_p = 0;
	}
      /* Function parameters cannot be constexpr.  If we saw one, moan
         and pretend it wasn't there.  */
      else if (constexpr_p)
        {
          error_at (declspecs->locations[ds_constexpr],
		    "a parameter cannot be declared %qs", "constexpr");
          constexpr_p = 0;
        }
      if (constinit_p)
	{
	  error_at (declspecs->locations[ds_constinit],
		    "a parameter cannot be declared %qs", "constinit");
	  constinit_p = 0;
	}
      if (consteval_p)
	{
	  error_at (declspecs->locations[ds_consteval],
		    "a parameter cannot be declared %qs", "consteval");
	  consteval_p = 0;
	}
    }

  /* Give error if `virtual' is used outside of class declaration.  */
  if (virtualp
      && (current_class_name == NULL_TREE || decl_context != FIELD))
    {
      error_at (declspecs->locations[ds_virtual],
		"%<virtual%> outside class declaration");
      virtualp = 0;
    }

  if (innermost_code == cdk_decomp)
    {
      location_t loc = (declarator->kind == cdk_reference
			? declarator->declarator->id_loc : declarator->id_loc);
      if (inlinep)
	error_at (declspecs->locations[ds_inline],
		  "structured binding declaration cannot be %qs", "inline");
      if (typedef_p)
	error_at (declspecs->locations[ds_typedef],
		  "structured binding declaration cannot be %qs", "typedef");
      if (constexpr_p && !concept_p)
	error_at (declspecs->locations[ds_constexpr], "structured "
		  "binding declaration cannot be %qs", "constexpr");
      if (consteval_p)
	error_at (declspecs->locations[ds_consteval], "structured "
		  "binding declaration cannot be %qs", "consteval");
      if (thread_p && cxx_dialect < cxx20)
	pedwarn (declspecs->locations[ds_thread], OPT_Wc__20_extensions,
		 "structured binding declaration can be %qs only in "
		 "%<-std=c++20%> or %<-std=gnu++20%>",
		 declspecs->gnu_thread_keyword_p
		 ? "__thread" : "thread_local");
      if (concept_p)
	error_at (declspecs->locations[ds_concept],
		  "structured binding declaration cannot be %qs", "concept");
      /* [dcl.struct.bind] "A cv that includes volatile is deprecated."  */
      if (type_quals & TYPE_QUAL_VOLATILE)
	warning_at (declspecs->locations[ds_volatile], OPT_Wvolatile,
		    "%<volatile%>-qualified structured binding is deprecated");
      switch (storage_class)
	{
	case sc_none:
	  break;
	case sc_register:
	  error_at (loc, "structured binding declaration cannot be %qs",
		    "register");
	  break;
	case sc_static:
	  if (cxx_dialect < cxx20)
	    pedwarn (loc, OPT_Wc__20_extensions,
		     "structured binding declaration can be %qs only in "
		     "%<-std=c++20%> or %<-std=gnu++20%>", "static");
	  break;
	case sc_extern:
	  error_at (loc, "structured binding declaration cannot be %qs",
		    "extern");
	  break;
	case sc_mutable:
	  error_at (loc, "structured binding declaration cannot be %qs",
		    "mutable");
	  break;
	case sc_auto:
	  error_at (loc, "structured binding declaration cannot be "
		    "C++98 %<auto%>");
	  break;
	default:
	  gcc_unreachable ();
	}
      if (TREE_CODE (type) != TEMPLATE_TYPE_PARM
	  || TYPE_IDENTIFIER (type) != auto_identifier)
	{
	  if (type != error_mark_node)
	    {
	      error_at (loc, "structured binding declaration cannot have "
			"type %qT", type);
	      inform (loc,
		      "type must be cv-qualified %<auto%> or reference to "
		      "cv-qualified %<auto%>");
	    }
	  type = build_qualified_type (make_auto (), type_quals);
	  declspecs->type = type;
	}
      inlinep = 0;
      typedef_p = 0;
      constexpr_p = 0;
      consteval_p = 0;
      concept_p = 0;
      if (storage_class != sc_static)
	{
	  storage_class = sc_none;
	  declspecs->storage_class = sc_none;
	}
    }

  /* Static anonymous unions are dealt with here.  */
  if (staticp && decl_context == TYPENAME
      && declspecs->type
      && ANON_AGGR_TYPE_P (declspecs->type))
    decl_context = FIELD;

  /* Warn about storage classes that are invalid for certain
     kinds of declarations (parameters, typenames, etc.).  */
  if (thread_p
      && ((storage_class
	   && storage_class != sc_extern
	   && storage_class != sc_static)
	  || typedef_p))
    {
      location_t loc
	= min_location (declspecs->locations[ds_thread],
			declspecs->locations[ds_storage_class]);
      error_at (loc, "multiple storage classes in declaration of %qs", name);
      thread_p = false;
    }
  if (decl_context != NORMAL
      && ((storage_class != sc_none
	   && storage_class != sc_mutable)
	  || thread_p))
    {
      if ((decl_context == PARM || decl_context == CATCHPARM)
	  && (storage_class == sc_register
	      || storage_class == sc_auto))
	;
      else if (typedef_p)
	;
      else if (decl_context == FIELD
	       /* C++ allows static class elements.  */
	       && storage_class == sc_static)
	/* C++ also allows inlines and signed and unsigned elements,
	   but in those cases we don't come in here.  */
	;
      else
	{
	  location_t loc
	    = min_location (declspecs->locations[ds_thread],
			    declspecs->locations[ds_storage_class]);
	  if (decl_context == FIELD)
	    error_at (loc, "storage class specified for %qs", name);
	  else if (decl_context == PARM || decl_context == CATCHPARM)
	    error_at (loc, "storage class specified for parameter %qs", name);
	  else
	    error_at (loc, "storage class specified for typename");
	  if (storage_class == sc_register
	      || storage_class == sc_auto
	      || storage_class == sc_extern
	      || thread_p)
	    storage_class = sc_none;
	}
    }
  else if (storage_class == sc_extern && funcdef_flag
	   && ! toplevel_bindings_p ())
    error ("nested function %qs declared %<extern%>", name);
  else if (toplevel_bindings_p ())
    {
      if (storage_class == sc_auto)
	error_at (declspecs->locations[ds_storage_class],
		  "top-level declaration of %qs specifies %<auto%>", name);
    }
  else if (thread_p
	   && storage_class != sc_extern
	   && storage_class != sc_static)
    {
      if (declspecs->gnu_thread_keyword_p)
	pedwarn (declspecs->locations[ds_thread],
		 0, "function-scope %qs implicitly auto and "
		 "declared %<__thread%>", name);

      /* When thread_local is applied to a variable of block scope the
	 storage-class-specifier static is implied if it does not appear
	 explicitly.  */
      storage_class = declspecs->storage_class = sc_static;
      staticp = 1;
    }

  if (storage_class && friendp)
    {
      error_at (min_location (declspecs->locations[ds_thread],
			      declspecs->locations[ds_storage_class]),
		"storage class specifiers invalid in friend function "
		"declarations");
      storage_class = sc_none;
      staticp = 0;
    }

  if (!id_declarator)
    unqualified_id = NULL_TREE;
  else
    {
      unqualified_id = id_declarator->u.id.unqualified_name;
      switch (TREE_CODE (unqualified_id))
	{
	case BIT_NOT_EXPR:
	  unqualified_id = TREE_OPERAND (unqualified_id, 0);
	  if (TYPE_P (unqualified_id))
	    unqualified_id = constructor_name (unqualified_id);
	  break;

	case IDENTIFIER_NODE:
	case TEMPLATE_ID_EXPR:
	  break;

	default:
	  gcc_unreachable ();
	}
    }

  if (declspecs->std_attributes)
    {
      location_t attr_loc = declspecs->locations[ds_std_attribute];
      if (warning_at (attr_loc, OPT_Wattributes, "attribute ignored"))
	inform (attr_loc, "an attribute that appertains to a type-specifier "
		"is ignored");
    }

  /* Determine the type of the entity declared by recurring on the
     declarator.  */
  for (; declarator; declarator = declarator->declarator)
    {
      const cp_declarator *inner_declarator;
      tree attrs;

      if (type == error_mark_node)
	return error_mark_node;

      attrs = declarator->attributes;
      if (attrs)
	{
	  int attr_flags;

	  attr_flags = 0;
	  if (declarator->kind == cdk_id)
	    attr_flags |= (int) ATTR_FLAG_DECL_NEXT;
	  if (declarator->kind == cdk_function)
	    attr_flags |= (int) ATTR_FLAG_FUNCTION_NEXT;
	  if (declarator->kind == cdk_array)
	    attr_flags |= (int) ATTR_FLAG_ARRAY_NEXT;
	  tree late_attrs = NULL_TREE;
	  if (decl_context != PARM && decl_context != TYPENAME)
	    /* Assume that any attributes that get applied late to
	       templates will DTRT when applied to the declaration
	       as a whole.  */
	    late_attrs = splice_template_attributes (&attrs, type);
	  returned_attrs = decl_attributes (&type,
					    chainon (returned_attrs, attrs),
					    attr_flags);
	  returned_attrs = chainon (late_attrs, returned_attrs);
	}

      inner_declarator = declarator->declarator;

      /* We don't want to warn in parameter context because we don't
	 yet know if the parse will succeed, and this might turn out
	 to be a constructor call.  */
      if (decl_context != PARM
	  && decl_context != TYPENAME
	  && !typedef_p
	  && declarator->parenthesized != UNKNOWN_LOCATION
	  /* If the type is class-like and the inner name used a
	     global namespace qualifier, we need the parens.
	     Unfortunately all we can tell is whether a qualified name
	     was used or not.  */
	  && !(inner_declarator
	       && inner_declarator->kind == cdk_id
	       && inner_declarator->u.id.qualifying_scope
	       && (MAYBE_CLASS_TYPE_P (type)
		   || TREE_CODE (type) == ENUMERAL_TYPE)))
	{
	  if (warning_at (declarator->parenthesized, OPT_Wparentheses,
			  "unnecessary parentheses in declaration of %qs",
			  name))
	    {
	      gcc_rich_location iloc (declarator->parenthesized);
	      iloc.add_fixit_remove (get_start (declarator->parenthesized));
	      iloc.add_fixit_remove (get_finish (declarator->parenthesized));
	      inform (&iloc, "remove parentheses");
	    }
	}
      if (declarator->kind == cdk_id || declarator->kind == cdk_decomp)
	break;

      switch (declarator->kind)
	{
	case cdk_array:
	  type = create_array_type_for_decl (dname, type,
					     declarator->u.array.bounds,
					     declarator->id_loc);
	  if (!valid_array_size_p (dname
				   ? declarator->id_loc : input_location,
				   type, dname))
	    type = error_mark_node;

	  if (declarator->std_attributes)
	    /* [dcl.array]/1:

	       The optional attribute-specifier-seq appertains to the
	       array.  */
	    returned_attrs = chainon (returned_attrs,
				      declarator->std_attributes);
	  break;

	case cdk_function:
	  {
	    tree arg_types;
	    int funcdecl_p;

	    /* Declaring a function type.  */

	    /* Pick up type qualifiers which should be applied to `this'.  */
	    memfn_quals = declarator->u.function.qualifiers;
	    /* Pick up virt-specifiers.  */
            virt_specifiers = declarator->u.function.virt_specifiers;
	    /* And ref-qualifier, too */
	    rqual = declarator->u.function.ref_qualifier;
	    /* And tx-qualifier.  */
	    tree tx_qual = declarator->u.function.tx_qualifier;
	    /* Pick up the exception specifications.  */
	    raises = declarator->u.function.exception_specification;
	    /* If the exception-specification is ill-formed, let's pretend
	       there wasn't one.  */
	    if (raises == error_mark_node)
	      raises = NULL_TREE;

	    if (reqs)
	      error_at (location_of (reqs), "requires-clause on return type");
	    reqs = declarator->u.function.requires_clause;

	    /* Say it's a definition only for the CALL_EXPR
	       closest to the identifier.  */
	    funcdecl_p = inner_declarator && inner_declarator->kind == cdk_id;

	    /* Handle a late-specified return type.  */
	    tree late_return_type = declarator->u.function.late_return_type;
	    if (tree auto_node = type_uses_auto (type))
	      {
		if (!late_return_type)
		  {
		    if (!funcdecl_p)
		      /* auto (*fp)() = f; is OK.  */;
		    else if (current_class_type
			     && LAMBDA_TYPE_P (current_class_type))
		      /* OK for C++11 lambdas.  */;
		    else if (cxx_dialect < cxx14)
		      {
			error_at (typespec_loc, "%qs function uses "
				  "%<auto%> type specifier without "
				  "trailing return type", name);
			inform (typespec_loc,
				"deduced return type only available "
				"with %<-std=c++14%> or %<-std=gnu++14%>");
		      }
		    else if (virtualp)
		      {
			error_at (typespec_loc, "virtual function "
				  "cannot have deduced return type");
			virtualp = false;
		      }
		  }
		else if (!is_auto (type) && sfk != sfk_conversion)
		  {
		    error_at (typespec_loc, "%qs function with trailing "
			      "return type has %qT as its type rather "
			      "than plain %<auto%>", name, type);
		    return error_mark_node;
		  }
		else if (is_auto (type) && AUTO_IS_DECLTYPE (type))
		  {
		    if (funcdecl_p)
		      error_at (typespec_loc,
				"%qs function with trailing return type "
				"has %<decltype(auto)%> as its type "
				"rather than plain %<auto%>", name);
		    else
		      error_at (typespec_loc,
				"invalid use of %<decltype(auto)%>");
		    return error_mark_node;
		  }
		tree tmpl = CLASS_PLACEHOLDER_TEMPLATE (auto_node);
		if (!tmpl)
		  if (tree late_auto = type_uses_auto (late_return_type))
		    tmpl = CLASS_PLACEHOLDER_TEMPLATE (late_auto);
		if (tmpl)
		  {
		    if (!funcdecl_p || !dguide_name_p (unqualified_id))
		      {
			error_at (typespec_loc, "deduced class "
				  "type %qD in function return type",
				  DECL_NAME (tmpl));
			inform (DECL_SOURCE_LOCATION (tmpl),
				"%qD declared here", tmpl);
			return error_mark_node;
		      }
		    else if (!late_return_type)
		      {
			error_at (declarator->id_loc, "deduction guide "
				  "for %qT must have trailing return "
				  "type", TREE_TYPE (tmpl));
			inform (DECL_SOURCE_LOCATION (tmpl),
				"%qD declared here", tmpl);
			return error_mark_node;
		      }
		    else if (CLASS_TYPE_P (late_return_type)
			      && CLASSTYPE_TEMPLATE_INFO (late_return_type)
			      && (CLASSTYPE_TI_TEMPLATE (late_return_type)
				  == tmpl))
		      /* OK */;
		    else
		      error ("trailing return type %qT of deduction guide "
			      "is not a specialization of %qT",
			      late_return_type, TREE_TYPE (tmpl));
		  }
	      }
	    else if (late_return_type
		     && sfk != sfk_conversion)
	      {
		if (late_return_type == error_mark_node)
		  return error_mark_node;
		if (cxx_dialect < cxx11)
		  /* Not using maybe_warn_cpp0x because this should
		     always be an error.  */
		  error_at (typespec_loc,
			    "trailing return type only available "
			    "with %<-std=c++11%> or %<-std=gnu++11%>");
		else
		  error_at (typespec_loc, "%qs function with trailing "
			    "return type not declared with %<auto%> "
			    "type specifier", name);
		return error_mark_node;
	      }
	    if (late_return_type && sfk == sfk_conversion)
	      {
		error ("a conversion function cannot have a trailing return type");
		return error_mark_node;
	      }
	    type = splice_late_return_type (type, late_return_type);
	    if (type == error_mark_node)
	      return error_mark_node;

	    if (late_return_type)
	      {
		late_return_type_p = true;
		type_quals = cp_type_quals (type);
	      }

	    if (type_quals != TYPE_UNQUALIFIED)
	      {
		if (SCALAR_TYPE_P (type) || VOID_TYPE_P (type))
		  warning_at (typespec_loc, OPT_Wignored_qualifiers, "type "
			      "qualifiers ignored on function return type");
		/* [dcl.fct] "A volatile-qualified return type is
		   deprecated."  */
		if (type_quals & TYPE_QUAL_VOLATILE)
		  warning_at (typespec_loc, OPT_Wvolatile,
			      "%<volatile%>-qualified return type is "
			      "deprecated");

		/* We now know that the TYPE_QUALS don't apply to the
		   decl, but to its return type.  */
		type_quals = TYPE_UNQUALIFIED;
	      }

	    /* Error about some types functions can't return.  */

	    if (TREE_CODE (type) == FUNCTION_TYPE)
	      {
		error_at (typespec_loc, "%qs declared as function returning "
			  "a function", name);
		return error_mark_node;
	      }
	    if (TREE_CODE (type) == ARRAY_TYPE)
	      {
		error_at (typespec_loc, "%qs declared as function returning "
			  "an array", name);
		return error_mark_node;
	      }
	    if (constinit_p && funcdecl_p)
	      {
		error_at (declspecs->locations[ds_constinit],
			  "%<constinit%> on function return type is not "
			  "allowed");
		return error_mark_node;
	      }

	    if (check_decltype_auto (typespec_loc, type))
	      return error_mark_node;

	    if (ctype == NULL_TREE
		&& decl_context == FIELD
		&& funcdecl_p
		&& friendp == 0)
	      ctype = current_class_type;

	    if (ctype && (sfk == sfk_constructor
			  || sfk == sfk_destructor))
	      {
		/* We are within a class's scope. If our declarator name
		   is the same as the class name, and we are defining
		   a function, then it is a constructor/destructor, and
		   therefore returns a void type.  */

		/* ISO C++ 12.4/2.  A destructor may not be declared
		   const or volatile.  A destructor may not be static.
		   A destructor may not be declared with ref-qualifier.

		   ISO C++ 12.1.  A constructor may not be declared
		   const or volatile.  A constructor may not be
		   virtual.  A constructor may not be static.
		   A constructor may not be declared with ref-qualifier. */
		if (staticp == 2)
		  error_at (declspecs->locations[ds_storage_class],
			    (flags == DTOR_FLAG)
			    ? G_("destructor cannot be static member "
				 "function")
			    : G_("constructor cannot be static member "
				 "function"));
		if (memfn_quals)
		  {
		    error ((flags == DTOR_FLAG)
			   ? G_("destructors may not be cv-qualified")
			   : G_("constructors may not be cv-qualified"));
		    memfn_quals = TYPE_UNQUALIFIED;
		  }

		if (rqual)
		  {
		    maybe_warn_cpp0x (CPP0X_REF_QUALIFIER);
		    error ((flags == DTOR_FLAG)
			   ? G_("destructors may not be ref-qualified")
			   : G_("constructors may not be ref-qualified"));
		    rqual = REF_QUAL_NONE;
		  }

		if (decl_context == FIELD
		    && !member_function_or_else (ctype,
						 current_class_type,
						 flags))
		  return error_mark_node;

		if (flags != DTOR_FLAG)
		  {
		    /* It's a constructor.  */
		    if (explicitp == 1)
		      explicitp = 2;
		    if (virtualp)
		      {
			permerror (declspecs->locations[ds_virtual],
				   "constructors cannot be declared %<virtual%>");
			virtualp = 0;
		      }
		    if (decl_context == FIELD
			&& sfk != sfk_constructor)
		      return error_mark_node;
		  }
		if (decl_context == FIELD)
		  staticp = 0;
	      }
	    else if (friendp)
	      {
		if (virtualp)
		  {
		    /* Cannot be both friend and virtual.  */
		    gcc_rich_location richloc (declspecs->locations[ds_virtual]);
		    richloc.add_range (declspecs->locations[ds_friend]);
		    error_at (&richloc, "virtual functions cannot be friends");
		    friendp = 0;
		  }
		if (decl_context == NORMAL)
		  error_at (declarator->id_loc,
			    "friend declaration not in class definition");
		if (current_function_decl && funcdef_flag)
		  {
		    error_at (declarator->id_loc,
			      "cannot define friend function %qs in a local "
			      "class definition", name);
		    friendp = 0;
		  }
		/* [class.friend]/6: A function can be defined in a friend
		   declaration if the function name is unqualified.  */
		if (funcdef_flag && in_namespace)
		  {
		    if (in_namespace == global_namespace)
		      error_at (declarator->id_loc,
				"friend function definition %qs cannot have "
				"a name qualified with %<::%>", name);
		    else
		      error_at (declarator->id_loc,
				"friend function definition %qs cannot have "
				"a name qualified with %<%D::%>", name,
				in_namespace);
		  }
	      }
	    else if (ctype && sfk == sfk_conversion)
	      {
		if (explicitp == 1)
		  {
		    maybe_warn_cpp0x (CPP0X_EXPLICIT_CONVERSION);
		    explicitp = 2;
		  }
	      }
	    else if (sfk == sfk_deduction_guide)
	      {
		if (explicitp == 1)
		  explicitp = 2;
	      }

	    tree pushed_scope = NULL_TREE;
	    if (funcdecl_p
		&& decl_context != FIELD
		&& inner_declarator->u.id.qualifying_scope
		&& CLASS_TYPE_P (inner_declarator->u.id.qualifying_scope))
	      pushed_scope
		= push_scope (inner_declarator->u.id.qualifying_scope);

	    arg_types = grokparms (declarator->u.function.parameters, &parms);

	    if (pushed_scope)
	      pop_scope (pushed_scope);

	    if (inner_declarator
		&& inner_declarator->kind == cdk_id
		&& inner_declarator->u.id.sfk == sfk_destructor
		&& arg_types != void_list_node)
	      {
		error_at (declarator->id_loc,
			  "destructors may not have parameters");
		arg_types = void_list_node;
		parms = NULL_TREE;
	      }

	    type = build_function_type (type, arg_types);

	    tree attrs = declarator->std_attributes;
	    if (tx_qual)
	      {
		tree att = build_tree_list (tx_qual, NULL_TREE);
		/* transaction_safe applies to the type, but
		   transaction_safe_dynamic applies to the function.  */
		if (is_attribute_p ("transaction_safe", tx_qual))
		  attrs = chainon (attrs, att);
		else
		  returned_attrs = chainon (returned_attrs, att);
	      }
	    if (attrs)
	      /* [dcl.fct]/2:

		 The optional attribute-specifier-seq appertains to
		 the function type.  */
	      cplus_decl_attributes (&type, attrs, 0);

	    if (raises)
	      type = build_exception_variant (type, raises);
	  }
	  break;

	case cdk_pointer:
	case cdk_reference:
	case cdk_ptrmem:
	  /* Filter out pointers-to-references and references-to-references.
	     We can get these if a TYPE_DECL is used.  */

	  if (TYPE_REF_P (type))
	    {
	      if (declarator->kind != cdk_reference)
		{
		  error ("cannot declare pointer to %q#T", type);
		  type = TREE_TYPE (type);
		}

	      /* In C++0x, we allow reference to reference declarations
		 that occur indirectly through typedefs [7.1.3/8 dcl.typedef]
		 and template type arguments [14.3.1/4 temp.arg.type]. The
		 check for direct reference to reference declarations, which
		 are still forbidden, occurs below. Reasoning behind the change
		 can be found in DR106, DR540, and the rvalue reference
		 proposals. */
	      else if (cxx_dialect == cxx98)
		{
		  error ("cannot declare reference to %q#T", type);
		  type = TREE_TYPE (type);
		}
	    }
	  else if (VOID_TYPE_P (type))
	    {
	      if (declarator->kind == cdk_reference)
		error ("cannot declare reference to %q#T", type);
	      else if (declarator->kind == cdk_ptrmem)
		error ("cannot declare pointer to %q#T member", type);
	    }

	  /* We now know that the TYPE_QUALS don't apply to the decl,
	     but to the target of the pointer.  */
	  type_quals = TYPE_UNQUALIFIED;

	  /* This code used to handle METHOD_TYPE, but I don't think it's
	     possible to get it here anymore.  */
	  gcc_assert (TREE_CODE (type) != METHOD_TYPE);
	  if (declarator->kind == cdk_ptrmem
	      && TREE_CODE (type) == FUNCTION_TYPE)
	    {
	      memfn_quals |= type_memfn_quals (type);
	      type = build_memfn_type (type,
				       declarator->u.pointer.class_type,
				       memfn_quals,
				       rqual);
	      if (type == error_mark_node)
		return error_mark_node;

	      rqual = REF_QUAL_NONE;
	      memfn_quals = TYPE_UNQUALIFIED;
	    }

	  if (TREE_CODE (type) == FUNCTION_TYPE
	      && (type_memfn_quals (type) != TYPE_UNQUALIFIED
		  || type_memfn_rqual (type) != REF_QUAL_NONE))
            error (declarator->kind == cdk_reference
                   ? G_("cannot declare reference to qualified function type %qT")
                   : G_("cannot declare pointer to qualified function type %qT"),
		   type);

	  /* When the pointed-to type involves components of variable size,
	     care must be taken to ensure that the size evaluation code is
	     emitted early enough to dominate all the possible later uses
	     and late enough for the variables on which it depends to have
	     been assigned.

	     This is expected to happen automatically when the pointed-to
	     type has a name/declaration of it's own, but special attention
	     is required if the type is anonymous.

	     We handle the NORMAL and FIELD contexts here by inserting a
	     dummy statement that just evaluates the size at a safe point
	     and ensures it is not deferred until e.g. within a deeper
	     conditional context (c++/43555).

	     We expect nothing to be needed here for PARM or TYPENAME.
	     Evaluating the size at this point for TYPENAME would
	     actually be incorrect, as we might be in the middle of an
	     expression with side effects on the pointed-to type size
	     "arguments" prior to the pointer declaration point and the
	     size evaluation could end up prior to the side effects.  */

	  if (!TYPE_NAME (type)
	      && (decl_context == NORMAL || decl_context == FIELD)
	      && at_function_scope_p ()
	      && variably_modified_type_p (type, NULL_TREE))
	    {
	      TYPE_NAME (type) = build_decl (UNKNOWN_LOCATION, TYPE_DECL,
					     NULL_TREE, type);
	      add_decl_expr (TYPE_NAME (type));
	    }

	  if (declarator->kind == cdk_reference)
	    {
	      /* In C++0x, the type we are creating a reference to might be
		 a typedef which is itself a reference type. In that case,
		 we follow the reference collapsing rules in
		 [7.1.3/8 dcl.typedef] to create the final reference type:

		 "If a typedef TD names a type that is a reference to a type
		 T, an attempt to create the type 'lvalue reference to cv TD'
		 creates the type 'lvalue reference to T,' while an attempt
		 to create the type "rvalue reference to cv TD' creates the
		 type TD."
              */
	      if (VOID_TYPE_P (type))
		/* We already gave an error.  */;
	      else if (TYPE_REF_P (type))
		{
		  if (declarator->u.reference.rvalue_ref)
		    /* Leave type alone.  */;
		  else
		    type = cp_build_reference_type (TREE_TYPE (type), false);
		}
	      else
		type = cp_build_reference_type
		  (type, declarator->u.reference.rvalue_ref);

	      /* In C++0x, we need this check for direct reference to
		 reference declarations, which are forbidden by
		 [8.3.2/5 dcl.ref]. Reference to reference declarations
		 are only allowed indirectly through typedefs and template
		 type arguments. Example:

		   void foo(int & &);      // invalid ref-to-ref decl

		   typedef int & int_ref;
		   void foo(int_ref &);    // valid ref-to-ref decl
	      */
	      if (inner_declarator && inner_declarator->kind == cdk_reference)
		error ("cannot declare reference to %q#T, which is not "
		       "a typedef or a template type argument", type);
	    }
	  else if (TREE_CODE (type) == METHOD_TYPE)
	    type = build_ptrmemfunc_type (build_pointer_type (type));
	  else if (declarator->kind == cdk_ptrmem)
	    {
	      gcc_assert (TREE_CODE (declarator->u.pointer.class_type)
			  != NAMESPACE_DECL);
	      if (declarator->u.pointer.class_type == error_mark_node)
		/* We will already have complained.  */
		type = error_mark_node;
	      else
		type = build_ptrmem_type (declarator->u.pointer.class_type,
					  type);
	    }
	  else
	    type = build_pointer_type (type);

	  /* Process a list of type modifier keywords (such as
	     const or volatile) that were given inside the `*' or `&'.  */

	  if (declarator->u.pointer.qualifiers)
	    {
	      type
		= cp_build_qualified_type (type,
					   declarator->u.pointer.qualifiers);
	      type_quals = cp_type_quals (type);
	    }

	  /* Apply C++11 attributes to the pointer, and not to the
	     type pointed to.  This is unlike what is done for GNU
	     attributes above.  It is to comply with [dcl.ptr]/1:

		 [the optional attribute-specifier-seq (7.6.1) appertains
		  to the pointer and not to the object pointed to].  */
	  if (declarator->std_attributes)
	    decl_attributes (&type, declarator->std_attributes,
			     0);

	  ctype = NULL_TREE;
	  break;

	case cdk_error:
	  break;

	default:
	  gcc_unreachable ();
	}
    }

  id_loc = declarator ? declarator->id_loc : input_location;

  if (innermost_code != cdk_function
    /* Don't check this if it can be the artifical decltype(auto)
       we created when building a constraint in a compound-requirement:
       that the type-constraint is plain is going to be checked in
       cp_parser_compound_requirement.  */
      && decl_context != TYPENAME
      && check_decltype_auto (id_loc, type))
    return error_mark_node;

  /* A `constexpr' specifier used in an object declaration declares
     the object as `const'.  */
  if (constexpr_p && innermost_code != cdk_function)
    {
      /* DR1688 says that a `constexpr' specifier in combination with
	 `volatile' is valid.  */

      if (!TYPE_REF_P (type))
	{
	  type_quals |= TYPE_QUAL_CONST;
	  type = cp_build_qualified_type (type, type_quals);
	}
    }

  if (unqualified_id && TREE_CODE (unqualified_id) == TEMPLATE_ID_EXPR
      && !FUNC_OR_METHOD_TYPE_P (type)
      && !variable_template_p (TREE_OPERAND (unqualified_id, 0)))
    {
      error ("template-id %qD used as a declarator",
	     unqualified_id);
      unqualified_id = dname;
    }

  /* If TYPE is a FUNCTION_TYPE, but the function name was explicitly
     qualified with a class-name, turn it into a METHOD_TYPE, unless
     we know that the function is static.  We take advantage of this
     opportunity to do other processing that pertains to entities
     explicitly declared to be class members.  Note that if DECLARATOR
     is non-NULL, we know it is a cdk_id declarator; otherwise, we
     would not have exited the loop above.  */
  if (declarator
      && declarator->kind == cdk_id
      && declarator->u.id.qualifying_scope
      && MAYBE_CLASS_TYPE_P (declarator->u.id.qualifying_scope))
    {
      ctype = declarator->u.id.qualifying_scope;
      ctype = TYPE_MAIN_VARIANT (ctype);
      template_count = num_template_headers_for_class (ctype);

      if (ctype == current_class_type)
	{
	  if (friendp)
	    {
	      permerror (declspecs->locations[ds_friend],
			 "member functions are implicitly "
			 "friends of their class");
	      friendp = 0;
	    }
	  else
	    permerror (id_loc, "extra qualification %<%T::%> on member %qs",
		       ctype, name);
	}
      else if (/* If the qualifying type is already complete, then we
		  can skip the following checks.  */
	       !COMPLETE_TYPE_P (ctype)
	       && (/* If the function is being defined, then
		      qualifying type must certainly be complete.  */
		   funcdef_flag
		   /* A friend declaration of "T::f" is OK, even if
		      "T" is a template parameter.  But, if this
		      function is not a friend, the qualifying type
		      must be a class.  */
		   || (!friendp && !CLASS_TYPE_P (ctype))
		   /* For a declaration, the type need not be
		      complete, if either it is dependent (since there
		      is no meaningful definition of complete in that
		      case) or the qualifying class is currently being
		      defined.  */
		   || !(dependent_type_p (ctype)
			|| currently_open_class (ctype)))
	       /* Check that the qualifying type is complete.  */
	       && !complete_type_or_else (ctype, NULL_TREE))
	return error_mark_node;
      else if (TREE_CODE (type) == FUNCTION_TYPE)
	{
	  if (current_class_type
	      && (!friendp || funcdef_flag || initialized))
	    {
	      error_at (id_loc, funcdef_flag || initialized
			? G_("cannot define member function %<%T::%s%> "
			     "within %qT")
			: G_("cannot declare member function %<%T::%s%> "
			     "within %qT"),
			ctype, name, current_class_type);
	      return error_mark_node;
	    }
	}
      else if (typedef_p && current_class_type)
	{
	  error_at (id_loc, "cannot declare member %<%T::%s%> within %qT",
		    ctype, name, current_class_type);
	  return error_mark_node;
	}
    }

  if (ctype == NULL_TREE && decl_context == FIELD && friendp == 0)
    ctype = current_class_type;

  /* Now TYPE has the actual type.  */

  if (returned_attrs)
    {
      if (attrlist)
	*attrlist = chainon (returned_attrs, *attrlist);
      else
	attrlist = &returned_attrs;
    }

  if (declarator
      && declarator->kind == cdk_id
      && declarator->std_attributes
      && attrlist != NULL)
    {
      /* [dcl.meaning]/1: The optional attribute-specifier-seq following
	 a declarator-id appertains to the entity that is declared.  */
      if (declarator->std_attributes != error_mark_node)
	*attrlist = chainon (*attrlist, declarator->std_attributes);
      else
	/* We should have already diagnosed the issue (c++/78344).  */
	gcc_assert (seen_error ());
    }

  /* Handle parameter packs. */
  if (parameter_pack_p)
    {
      if (decl_context == PARM)
        /* Turn the type into a pack expansion.*/
        type = make_pack_expansion (type);
      else
        error ("non-parameter %qs cannot be a parameter pack", name);
    }

  if ((decl_context == FIELD || decl_context == PARM)
      && !processing_template_decl
      && variably_modified_type_p (type, NULL_TREE))
    {
      if (decl_context == FIELD)
	error_at (id_loc,
		  "data member may not have variably modified type %qT", type);
      else
	error_at (id_loc,
		  "parameter may not have variably modified type %qT", type);
      type = error_mark_node;
    }

  if (explicitp == 1 || (explicitp && friendp))
    {
      /* [dcl.fct.spec] (C++11) The explicit specifier shall be used only
	 in the declaration of a constructor or conversion function within
	 a class definition.  */
      if (!current_class_type)
	error_at (declspecs->locations[ds_explicit],
		  "%<explicit%> outside class declaration");
      else if (friendp)
	error_at (declspecs->locations[ds_explicit],
		  "%<explicit%> in friend declaration");
      else
	error_at (declspecs->locations[ds_explicit],
		  "only declarations of constructors and conversion operators "
		  "can be %<explicit%>");
      explicitp = 0;
    }

  if (storage_class == sc_mutable)
    {
      location_t sloc = declspecs->locations[ds_storage_class];
      if (decl_context != FIELD || friendp)
	{
	  error_at (sloc, "non-member %qs cannot be declared %<mutable%>",
		    name);
	  storage_class = sc_none;
	}
      else if (decl_context == TYPENAME || typedef_p)
	{
	  error_at (sloc,
		    "non-object member %qs cannot be declared %<mutable%>",
		    name);
	  storage_class = sc_none;
	}
      else if (FUNC_OR_METHOD_TYPE_P (type))
	{
	  error_at (sloc, "function %qs cannot be declared %<mutable%>",
		    name);
	  storage_class = sc_none;
	}
      else if (staticp)
	{
	  error_at (sloc, "%<static%> %qs cannot be declared %<mutable%>",
		    name);
	  storage_class = sc_none;
	}
      else if (type_quals & TYPE_QUAL_CONST)
	{
	  error_at (sloc, "%<const%> %qs cannot be declared %<mutable%>",
		    name);
	  storage_class = sc_none;
	}
      else if (TYPE_REF_P (type))
	{
	  permerror (sloc, "reference %qs cannot be declared %<mutable%>",
		     name);
	  storage_class = sc_none;
	}
    }

  /* If this is declaring a typedef name, return a TYPE_DECL.  */
  if (typedef_p && decl_context != TYPENAME)
    {
      bool alias_p = decl_spec_seq_has_spec_p (declspecs, ds_alias);
      tree decl;

      if (funcdef_flag)
	{
	  if (decl_context == NORMAL)
	    error_at (id_loc,
		      "typedef may not be a function definition");
	  else
	    error_at (id_loc,
		      "typedef may not be a member function definition");
	  return error_mark_node;
	}

      /* This declaration:

	   typedef void f(int) const;

	 declares a function type which is not a member of any
	 particular class, but which is cv-qualified; for
	 example "f S::*" declares a pointer to a const-qualified
	 member function of S.  We record the cv-qualification in the
	 function type.  */
      if ((rqual || memfn_quals) && TREE_CODE (type) == FUNCTION_TYPE)
        {
          type = apply_memfn_quals (type, memfn_quals, rqual);
          
          /* We have now dealt with these qualifiers.  */
          memfn_quals = TYPE_UNQUALIFIED;
	  rqual = REF_QUAL_NONE;
        }

      if (type_uses_auto (type))
	{
	  if (alias_p)
	    error_at (declspecs->locations[ds_type_spec],
		      "%<auto%> not allowed in alias declaration");
	  else
	    error_at (declspecs->locations[ds_type_spec],
		      "typedef declared %<auto%>");
	  type = error_mark_node;
	}

      if (reqs)
	error_at (location_of (reqs), "requires-clause on typedef");

      if (id_declarator && declarator->u.id.qualifying_scope)
	{
	  error_at (id_loc, "typedef name may not be a nested-name-specifier");
	  type = error_mark_node;
	}

      if (decl_context == FIELD)
	decl = build_lang_decl_loc (id_loc, TYPE_DECL, unqualified_id, type);
      else
	decl = build_decl (id_loc, TYPE_DECL, unqualified_id, type);

      if (decl_context != FIELD)
	{
	  if (!current_function_decl)
	    DECL_CONTEXT (decl) = FROB_CONTEXT (current_namespace);
	  else if (DECL_MAYBE_IN_CHARGE_CDTOR_P (current_function_decl))
	    /* The TYPE_DECL is "abstract" because there will be
	       clones of this constructor/destructor, and there will
	       be copies of this TYPE_DECL generated in those
	       clones.  The decloning optimization (for space) may
               revert this subsequently if it determines that
               the clones should share a common implementation.  */
	    DECL_ABSTRACT_P (decl) = true;

	  set_originating_module (decl);
	}
      else if (current_class_type
	       && constructor_name_p (unqualified_id, current_class_type))
	permerror (id_loc, "ISO C++ forbids nested type %qD with same name "
		   "as enclosing class",
		   unqualified_id);

      /* If the user declares "typedef struct {...} foo" then the
	 struct will have an anonymous name.  Fill that name in now.
	 Nothing can refer to it, so nothing needs know about the name
	 change.  */
      if (type != error_mark_node
	  && unqualified_id
	  && TYPE_NAME (type)
	  && TREE_CODE (TYPE_NAME (type)) == TYPE_DECL
	  && TYPE_UNNAMED_P (type)
	  && declspecs->type_definition_p
	  && attributes_naming_typedef_ok (*attrlist)
	  && cp_type_quals (type) == TYPE_UNQUALIFIED)
	name_unnamed_type (type, decl);

      if (signed_p
	  || (typedef_decl && C_TYPEDEF_EXPLICITLY_SIGNED (typedef_decl)))
	C_TYPEDEF_EXPLICITLY_SIGNED (decl) = 1;

      bad_specifiers (decl, BSP_TYPE, virtualp,
		      memfn_quals != TYPE_UNQUALIFIED,
		      inlinep, friendp, raises != NULL_TREE,
		      declspecs->locations);

      if (alias_p)
	/* Acknowledge that this was written:
	     `using analias = atype;'.  */
	TYPE_DECL_ALIAS_P (decl) = 1;

      return decl;
    }

  /* Detect the case of an array type of unspecified size
     which came, as such, direct from a typedef name.
     We must copy the type, so that the array's domain can be
     individually set by the object's initializer.  */

  if (type && typedef_type
      && TREE_CODE (type) == ARRAY_TYPE && !TYPE_DOMAIN (type)
      && TYPE_MAIN_VARIANT (type) == TYPE_MAIN_VARIANT (typedef_type))
    type = build_cplus_array_type (TREE_TYPE (type), NULL_TREE);

  /* Detect where we're using a typedef of function type to declare a
     function. PARMS will not be set, so we must create it now.  */

  if (type == typedef_type && TREE_CODE (type) == FUNCTION_TYPE)
    {
      tree decls = NULL_TREE;
      tree args;

      for (args = TYPE_ARG_TYPES (type);
	   args && args != void_list_node;
	   args = TREE_CHAIN (args))
	{
	  tree decl = cp_build_parm_decl (NULL_TREE, NULL_TREE,
					  TREE_VALUE (args));

	  DECL_CHAIN (decl) = decls;
	  decls = decl;
	}

      parms = nreverse (decls);

      if (decl_context != TYPENAME)
	{
	  /* The qualifiers on the function type become the qualifiers on
	     the non-static member function. */
	  memfn_quals |= type_memfn_quals (type);
	  rqual = type_memfn_rqual (type);
	  type_quals = TYPE_UNQUALIFIED;
	  raises = TYPE_RAISES_EXCEPTIONS (type);
	}
    }

  /* If this is a type name (such as, in a cast or sizeof),
     compute the type and return it now.  */

  if (decl_context == TYPENAME)
    {
      /* Note that here we don't care about type_quals.  */

      /* Special case: "friend class foo" looks like a TYPENAME context.  */
      if (friendp)
	{
	  if (inlinep)
	    {
	      error ("%<inline%> specified for friend class declaration");
	      inlinep = 0;
	    }

	  if (!current_aggr)
	    {
	      /* Don't allow friend declaration without a class-key.  */
	      if (TREE_CODE (type) == TEMPLATE_TYPE_PARM)
		permerror (input_location, "template parameters cannot be friends");
	      else if (TREE_CODE (type) == TYPENAME_TYPE)
		permerror (input_location, "friend declaration requires class-key, "
			   "i.e. %<friend class %T::%D%>",
			   TYPE_CONTEXT (type), TYPENAME_TYPE_FULLNAME (type));
	      else
		permerror (input_location, "friend declaration requires class-key, "
			   "i.e. %<friend %#T%>",
			   type);
	    }

	  /* Only try to do this stuff if we didn't already give up.  */
	  if (type != integer_type_node)
	    {
	      /* A friendly class?  */
	      if (current_class_type)
		make_friend_class (current_class_type, TYPE_MAIN_VARIANT (type),
				   /*complain=*/true);
	      else
		error ("trying to make class %qT a friend of global scope",
		       type);

	      type = void_type_node;
	    }
	}
      else if (memfn_quals || rqual)
	{
	  if (ctype == NULL_TREE
	      && TREE_CODE (type) == METHOD_TYPE)
	    ctype = TYPE_METHOD_BASETYPE (type);

	  if (ctype)
	    type = build_memfn_type (type, ctype, memfn_quals, rqual);
	  /* Core issue #547: need to allow this in template type args.
	     Allow it in general in C++11 for alias-declarations.  */
	  else if ((template_type_arg || cxx_dialect >= cxx11)
		   && TREE_CODE (type) == FUNCTION_TYPE)
	    type = apply_memfn_quals (type, memfn_quals, rqual);
	  else
	    error ("invalid qualifiers on non-member function type");
	}

      if (reqs)
	error_at (location_of (reqs), "requires-clause on type-id");

      return type;
    }
  else if (unqualified_id == NULL_TREE && decl_context != PARM
	   && decl_context != CATCHPARM
	   && TREE_CODE (type) != UNION_TYPE
	   && ! bitfield
	   && innermost_code != cdk_decomp)
    {
      error ("abstract declarator %qT used as declaration", type);
      return error_mark_node;
    }

  if (!FUNC_OR_METHOD_TYPE_P (type))
    {
      /* Only functions may be declared using an operator-function-id.  */
      if (dname && IDENTIFIER_ANY_OP_P (dname))
	{
	  error_at (id_loc, "declaration of %qD as non-function", dname);
	  return error_mark_node;
	}

      if (reqs)
	error_at (location_of (reqs),
		  "requires-clause on declaration of non-function type %qT",
		  type);
    }

  /* We don't check parameter types here because we can emit a better
     error message later.  */
  if (decl_context != PARM)
    {
      type = check_var_type (unqualified_id, type, id_loc);
      if (type == error_mark_node)
        return error_mark_node;
    }

  /* Now create the decl, which may be a VAR_DECL, a PARM_DECL
     or a FUNCTION_DECL, depending on DECL_CONTEXT and TYPE.  */

  if (decl_context == PARM || decl_context == CATCHPARM)
    {
      if (ctype || in_namespace)
	error ("cannot use %<::%> in parameter declaration");

      tree auto_node = type_uses_auto (type);
      if (auto_node && !(cxx_dialect >= cxx17 && template_parm_flag))
	{
	  if (cxx_dialect >= cxx14)
	    {
	      if (decl_context == PARM && AUTO_IS_DECLTYPE (auto_node))
		error_at (typespec_loc,
			  "cannot declare a parameter with %<decltype(auto)%>");
	      else if (tree c = CLASS_PLACEHOLDER_TEMPLATE (auto_node))
		{
		  auto_diagnostic_group g;
		  error_at (typespec_loc,
			    "class template placeholder %qE not permitted "
			    "in this context", c);
		  if (decl_context == PARM && cxx_dialect >= cxx20)
		    inform (typespec_loc, "use %<auto%> for an "
			    "abbreviated function template");
		}
	      else
		error_at (typespec_loc,
			  "%<auto%> parameter not permitted in this context");
	    }
	  else
	    error_at (typespec_loc, "parameter declared %<auto%>");
	  type = error_mark_node;
	}

      /* A parameter declared as an array of T is really a pointer to T.
	 One declared as a function is really a pointer to a function.
	 One declared as a member is really a pointer to member.  */

      if (TREE_CODE (type) == ARRAY_TYPE)
	{
	  /* Transfer const-ness of array into that of type pointed to.  */
	  type = build_pointer_type (TREE_TYPE (type));
	  type_quals = TYPE_UNQUALIFIED;
	  array_parameter_p = true;
	}
      else if (TREE_CODE (type) == FUNCTION_TYPE)
	type = build_pointer_type (type);
    }

  if (ctype && TREE_CODE (type) == FUNCTION_TYPE && staticp < 2
      && !(unqualified_id
	   && identifier_p (unqualified_id)
	   && IDENTIFIER_NEWDEL_OP_P (unqualified_id)))
    {
      cp_cv_quals real_quals = memfn_quals;
      if (cxx_dialect < cxx14 && constexpr_p
	  && sfk != sfk_constructor && sfk != sfk_destructor)
	real_quals |= TYPE_QUAL_CONST;
      type = build_memfn_type (type, ctype, real_quals, rqual);
    }

  {
    tree decl = NULL_TREE;

    if (decl_context == PARM)
      {
	decl = cp_build_parm_decl (NULL_TREE, unqualified_id, type);
	DECL_ARRAY_PARAMETER_P (decl) = array_parameter_p;

	bad_specifiers (decl, BSP_PARM, virtualp,
			memfn_quals != TYPE_UNQUALIFIED,
			inlinep, friendp, raises != NULL_TREE,
			declspecs->locations);
      }
    else if (decl_context == FIELD)
      {
	if (!staticp && !friendp && !FUNC_OR_METHOD_TYPE_P (type))
	  if (tree auto_node = type_uses_auto (type))
	    {
	      location_t tloc = declspecs->locations[ds_type_spec];
	      if (CLASS_PLACEHOLDER_TEMPLATE (auto_node))
		error_at (tloc, "invalid use of template-name %qE without an "
			  "argument list",
			  CLASS_PLACEHOLDER_TEMPLATE (auto_node));
	      else
		error_at (tloc, "non-static data member declared with "
			  "placeholder %qT", auto_node);
	      type = error_mark_node;
	    }

	/* The C99 flexible array extension.  */
	if (!staticp && TREE_CODE (type) == ARRAY_TYPE
	    && TYPE_DOMAIN (type) == NULL_TREE)
	  {
	    if (ctype
		&& (TREE_CODE (ctype) == UNION_TYPE
		    || TREE_CODE (ctype) == QUAL_UNION_TYPE))
	      {
		error_at (id_loc, "flexible array member in union");
		type = error_mark_node;
	      }
	    else
	      {
		/* Array is a flexible member.  */
		if (name)
		  pedwarn (id_loc, OPT_Wpedantic,
			   "ISO C++ forbids flexible array member %qs", name);
		else
		  pedwarn (input_location, OPT_Wpedantic,
			   "ISO C++ forbids flexible array members");

		/* Flexible array member has a null domain.  */
		type = build_cplus_array_type (TREE_TYPE (type), NULL_TREE);
	      }
	  }

	if (type == error_mark_node)
	  {
	    /* Happens when declaring arrays of sizes which
	       are error_mark_node, for example.  */
	    decl = NULL_TREE;
	  }
	else if (in_namespace && !friendp)
	  {
	    /* Something like struct S { int N::j; };  */
	    error_at (id_loc, "invalid use of %<::%>");
	    return error_mark_node;
	  }
	else if (FUNC_OR_METHOD_TYPE_P (type) && unqualified_id)
	  {
	    int publicp = 0;
	    tree function_context;

	    if (friendp == 0)
	      {
		/* This should never happen in pure C++ (the check
		   could be an assert).  It could happen in
		   Objective-C++ if someone writes invalid code that
		   uses a function declaration for an instance
		   variable or property (instance variables and
		   properties are parsed as FIELD_DECLs, but they are
		   part of an Objective-C class, not a C++ class).
		   That code is invalid and is caught by this
		   check.  */
		if (!ctype)
		  {
		    error ("declaration of function %qD in invalid context",
			   unqualified_id);
		    return error_mark_node;
		  }

		/* ``A union may [ ... ] not [ have ] virtual functions.''
		   ARM 9.5 */
		if (virtualp && TREE_CODE (ctype) == UNION_TYPE)
		  {
		    error_at (declspecs->locations[ds_virtual],
			      "function %qD declared %<virtual%> inside a union",
			      unqualified_id);
		    return error_mark_node;
		  }

		if (virtualp
		    && identifier_p (unqualified_id)
		    && IDENTIFIER_NEWDEL_OP_P (unqualified_id))
		  {
		    error_at (declspecs->locations[ds_virtual],
			      "%qD cannot be declared %<virtual%>, since it "
			      "is always static", unqualified_id);
		    virtualp = 0;
		  }
	      }

	    /* Check that the name used for a destructor makes sense.  */
	    if (sfk == sfk_destructor)
	      {
		tree uqname = id_declarator->u.id.unqualified_name;

		if (!ctype)
		  {
		    gcc_assert (friendp);
		    error_at (id_loc, "expected qualified name in friend "
			      "declaration for destructor %qD", uqname);
		    return error_mark_node;
		  }

		if (!check_dtor_name (ctype, TREE_OPERAND (uqname, 0)))
		  {
		    error_at (id_loc, "declaration of %qD as member of %qT",
			      uqname, ctype);
		    return error_mark_node;
		  }
                if (concept_p)
                  {
                    error_at (declspecs->locations[ds_concept],
			      "a destructor cannot be %qs", "concept");
                    return error_mark_node;
                  }
		if (constexpr_p && cxx_dialect < cxx20)
		  {
		    error_at (declspecs->locations[ds_constexpr],
			      "%<constexpr%> destructors only available"
			      " with %<-std=c++20%> or %<-std=gnu++20%>");
		    return error_mark_node;
		  }
		if (consteval_p)
		  {
		    error_at (declspecs->locations[ds_consteval],
			      "a destructor cannot be %qs", "consteval");
		    return error_mark_node;
		  }
	      }
	    else if (sfk == sfk_constructor && friendp && !ctype)
	      {
		error ("expected qualified name in friend declaration "
		       "for constructor %qD",
		       id_declarator->u.id.unqualified_name);
		return error_mark_node;
	      }
	    if (sfk == sfk_constructor)
	      if (concept_p)
		{
		  error_at (declspecs->locations[ds_concept],
			    "a constructor cannot be %<concept%>");
		  return error_mark_node;
		}
	    if (concept_p)
	      {
		error_at (declspecs->locations[ds_concept],
			  "a concept cannot be a member function");
		concept_p = false;
	      }
	    else if (consteval_p
		     && identifier_p (unqualified_id)
		     && IDENTIFIER_NEWDEL_OP_P (unqualified_id))
	      {
		error_at (declspecs->locations[ds_consteval],
			  "%qD cannot be %qs", unqualified_id, "consteval");
		consteval_p = false;
	      }

	    if (TREE_CODE (unqualified_id) == TEMPLATE_ID_EXPR)
	      {
		tree tmpl = TREE_OPERAND (unqualified_id, 0);
		if (variable_template_p (tmpl))
		  {
		    error_at (id_loc, "specialization of variable template "
			      "%qD declared as function", tmpl);
		    inform (DECL_SOURCE_LOCATION (tmpl),
			    "variable template declared here");
		    return error_mark_node;
		  }
	      }

	    /* Tell grokfndecl if it needs to set TREE_PUBLIC on the node.  */
	    function_context
	      = (ctype != NULL_TREE
		 ? decl_function_context (TYPE_MAIN_DECL (ctype)) : NULL_TREE);
	    publicp = ((! friendp || ! staticp)
		       && function_context == NULL_TREE);

	    decl = grokfndecl (ctype, type,
			       TREE_CODE (unqualified_id) != TEMPLATE_ID_EXPR
			       ? unqualified_id : dname,
			       parms,
			       unqualified_id,
			       declspecs,
			       reqs,
			       virtualp, flags, memfn_quals, rqual, raises,
			       friendp ? -1 : 0, friendp, publicp,
			       inlinep | (2 * constexpr_p) | (4 * concept_p)
				       | (8 * consteval_p),
			       initialized == SD_DELETED, sfk,
			       funcdef_flag, late_return_type_p,
			       template_count, in_namespace,
			       attrlist, id_loc);
            decl = set_virt_specifiers (decl, virt_specifiers);
	    if (decl == NULL_TREE)
	      return error_mark_node;
#if 0
	    /* This clobbers the attrs stored in `decl' from `attrlist'.  */
	    /* The decl and setting of decl_attr is also turned off.  */
	    decl = build_decl_attribute_variant (decl, decl_attr);
#endif

	    /* [class.conv.ctor]

	       A constructor declared without the function-specifier
	       explicit that can be called with a single parameter
	       specifies a conversion from the type of its first
	       parameter to the type of its class.  Such a constructor
	       is called a converting constructor.  */
	    if (explicitp == 2)
	      DECL_NONCONVERTING_P (decl) = 1;

	    if (declspecs->explicit_specifier)
	      store_explicit_specifier (decl, declspecs->explicit_specifier);
	  }
	else if (!staticp
		 && ((current_class_type
		      && same_type_p (TYPE_MAIN_VARIANT (type),
				      current_class_type))
		     || (!dependent_type_p (type)
			 && !COMPLETE_TYPE_P (complete_type (type))
			 && (!complete_or_array_type_p (type)
			     || initialized == SD_UNINITIALIZED))))
	  {
	    if (TREE_CODE (type) != ARRAY_TYPE
		|| !COMPLETE_TYPE_P (TREE_TYPE (type)))
	      {
		if (unqualified_id)
		  {
		    error_at (id_loc, "field %qD has incomplete type %qT",
			      unqualified_id, type);
		    cxx_incomplete_type_inform (strip_array_types (type));
		  }
		else
		  error ("name %qT has incomplete type", type);

		type = error_mark_node;
		decl = NULL_TREE;
	      }
	  }
	else if (!verify_type_context (input_location,
				       staticp
				       ? TCTX_STATIC_STORAGE
				       : TCTX_FIELD, type))
	  {
	    type = error_mark_node;
	    decl = NULL_TREE;
	  }
	else
	  {
	    if (friendp)
	      {
		if (unqualified_id)
		  error_at (id_loc,
			    "%qE is neither function nor member function; "
			    "cannot be declared friend", unqualified_id);
		else
		  error ("unnamed field is neither function nor member "
			 "function; cannot be declared friend");
		return error_mark_node;
	      }
	    decl = NULL_TREE;
	  }

	if (friendp)
	  {
	    /* Packages tend to use GNU attributes on friends, so we only
	       warn for standard attributes.  */
	    if (attrlist && !funcdef_flag && cxx11_attribute_p (*attrlist))
	      {
		*attrlist = NULL_TREE;
		if (warning_at (id_loc, OPT_Wattributes, "attribute ignored"))
		  inform (id_loc, "an attribute that appertains to a friend "
			  "declaration that is not a definition is ignored");
	      }
	    /* Friends are treated specially.  */
	    if (ctype == current_class_type)
	      ;  /* We already issued a permerror.  */
	    else if (decl && DECL_NAME (decl))
	      {
		set_originating_module (decl, true);
		
		if (initialized)
		  /* Kludge: We need funcdef_flag to be true in do_friend for
		     in-class defaulted functions, but that breaks grokfndecl.
		     So set it here.  */
		  funcdef_flag = true;

		if (template_class_depth (current_class_type) == 0)
		  {
		    decl = check_explicit_specialization
		      (unqualified_id, decl, template_count,
		       2 * funcdef_flag + 4);
		    if (decl == error_mark_node)
		      return error_mark_node;
		  }

		tree scope = ctype ? ctype : in_namespace;
		decl = do_friend (scope, unqualified_id, decl,
				  flags, funcdef_flag);
		return decl;
	      }
	    else
	      return error_mark_node;
	  }

	/* Structure field.  It may not be a function, except for C++.  */

	if (decl == NULL_TREE)
	  {
	    if (staticp)
	      {
		/* C++ allows static class members.  All other work
		   for this is done by grokfield.  */
		decl = build_lang_decl_loc (id_loc, VAR_DECL,
					    unqualified_id, type);
		set_linkage_for_static_data_member (decl);
		if (concept_p)
		  error_at (declspecs->locations[ds_concept],
			    "static data member %qE declared %qs",
			    unqualified_id, "concept");
		else if (constexpr_p && !initialized)
		  {
		    error_at (DECL_SOURCE_LOCATION (decl),
			      "%<constexpr%> static data member %qD must "
			      "have an initializer", decl);
		    constexpr_p = false;
		  }
		if (consteval_p)
		  error_at (declspecs->locations[ds_consteval],
			    "static data member %qE declared %qs",
			    unqualified_id, "consteval");

		if (inlinep)
		  mark_inline_variable (decl, declspecs->locations[ds_inline]);

		if (!DECL_VAR_DECLARED_INLINE_P (decl)
		    && !(cxx_dialect >= cxx17 && constexpr_p))
		  /* Even if there is an in-class initialization, DECL
		     is considered undefined until an out-of-class
		     definition is provided, unless this is an inline
		     variable.  */
		  DECL_EXTERNAL (decl) = 1;

		if (thread_p)
		  {
		    CP_DECL_THREAD_LOCAL_P (decl) = true;
		    if (!processing_template_decl)
		      set_decl_tls_model (decl, decl_default_tls_model (decl));
		    if (declspecs->gnu_thread_keyword_p)
		      SET_DECL_GNU_TLS_P (decl);
		  }

		/* Set the constraints on the declaration.  */
		bool memtmpl = (current_template_depth
				> template_class_depth (current_class_type));
		if (memtmpl)
		  {
		    tree tmpl_reqs
		      = TEMPLATE_PARMS_CONSTRAINTS (current_template_parms);
		    tree ci = build_constraints (tmpl_reqs, NULL_TREE);
		    set_constraints (decl, ci);
		  }
	      }
	    else
	      {
		if (concept_p)
		  {
		    error_at (declspecs->locations[ds_concept],
			      "non-static data member %qE declared %qs",
			      unqualified_id, "concept");
		    concept_p = false;
		    constexpr_p = false;
		  }
		else if (constexpr_p)
		  {
		    error_at (declspecs->locations[ds_constexpr],
			      "non-static data member %qE declared %qs",
			      unqualified_id, "constexpr");
		    constexpr_p = false;
		  }
		if (constinit_p)
		  {
		    error_at (declspecs->locations[ds_constinit],
			      "non-static data member %qE declared %qs",
			      unqualified_id, "constinit");
		    constinit_p = false;
		  }
		if (consteval_p)
		  {
		    error_at (declspecs->locations[ds_consteval],
			      "non-static data member %qE declared %qs",
			      unqualified_id, "consteval");
		    consteval_p = false;
		  }
		decl = build_decl (id_loc, FIELD_DECL, unqualified_id, type);
		DECL_NONADDRESSABLE_P (decl) = bitfield;
		if (bitfield && !unqualified_id)
		  DECL_PADDING_P (decl) = 1;

		if (storage_class == sc_mutable)
		  {
		    DECL_MUTABLE_P (decl) = 1;
		    storage_class = sc_none;
		  }

		if (initialized)
		  {
		    /* An attempt is being made to initialize a non-static
		       member.  This is new in C++11.  */
		    maybe_warn_cpp0x (CPP0X_NSDMI, init_loc);

		    /* If this has been parsed with static storage class, but
		       errors forced staticp to be cleared, ensure NSDMI is
		       not present.  */
		    if (declspecs->storage_class == sc_static)
		      DECL_INITIAL (decl) = error_mark_node;
		  }
	      }

	    bad_specifiers (decl, BSP_FIELD, virtualp,
			    memfn_quals != TYPE_UNQUALIFIED,
			    staticp ? false : inlinep, friendp,
			    raises != NULL_TREE,
			    declspecs->locations);
	  }
      }
    else if (FUNC_OR_METHOD_TYPE_P (type))
      {
	tree original_name;
	int publicp = 0;

	if (!unqualified_id)
	  return error_mark_node;

	if (TREE_CODE (unqualified_id) == TEMPLATE_ID_EXPR)
	  original_name = dname;
	else
	  original_name = unqualified_id;
	// FIXME:gcc_assert (original_name == dname);

	if (storage_class == sc_auto)
	  error_at (declspecs->locations[ds_storage_class],
		    "storage class %<auto%> invalid for function %qs", name);
	else if (storage_class == sc_register)
	  error_at (declspecs->locations[ds_storage_class],
		    "storage class %<register%> invalid for function %qs",
		    name);
	else if (thread_p)
	  {
	    if (declspecs->gnu_thread_keyword_p)
	      error_at (declspecs->locations[ds_thread],
			"storage class %<__thread%> invalid for function %qs",
			name);
	    else
	      error_at (declspecs->locations[ds_thread],
			"storage class %<thread_local%> invalid for "
			"function %qs", name);
	  }

        if (virt_specifiers)
          error ("virt-specifiers in %qs not allowed outside a class "
		 "definition", name);
	/* Function declaration not at top level.
	   Storage classes other than `extern' are not allowed
	   and `extern' makes no difference.  */
	if (! toplevel_bindings_p ()
	    && (storage_class == sc_static
		|| decl_spec_seq_has_spec_p (declspecs, ds_inline))
	    && pedantic)
	  {
	    if (storage_class == sc_static)
	      pedwarn (declspecs->locations[ds_storage_class], OPT_Wpedantic, 
		       "%<static%> specifier invalid for function %qs "
		       "declared out of global scope", name);
	    else
	      pedwarn (declspecs->locations[ds_inline], OPT_Wpedantic, 
		       "%<inline%> specifier invalid for function %qs "
		       "declared out of global scope", name);
	  }

	if (ctype == NULL_TREE)
	  {
	    if (virtualp)
	      {
		error ("virtual non-class function %qs", name);
		virtualp = 0;
	      }
	    else if (sfk == sfk_constructor
		     || sfk == sfk_destructor)
	      {
		error (funcdef_flag
		       ? G_("%qs defined in a non-class scope")
		       : G_("%qs declared in a non-class scope"), name);
		sfk = sfk_none;
	      }
	  }
	if (consteval_p
	    && identifier_p (unqualified_id)
	    && IDENTIFIER_NEWDEL_OP_P (unqualified_id))
	  {
	    error_at (declspecs->locations[ds_consteval],
		      "%qD cannot be %qs", unqualified_id, "consteval");
	    consteval_p = false;
	  }

	/* Record whether the function is public.  */
	publicp = (ctype != NULL_TREE
		   || storage_class != sc_static);

	decl = grokfndecl (ctype, type, original_name, parms, unqualified_id,
			   declspecs,
                           reqs, virtualp, flags, memfn_quals, rqual, raises,
			   1, friendp,
			   publicp,
			   inlinep | (2 * constexpr_p) | (4 * concept_p)
				   | (8 * consteval_p),
			   initialized == SD_DELETED,
                           sfk,
                           funcdef_flag,
			   late_return_type_p,
			   template_count, in_namespace, attrlist,
			   id_loc);
	if (decl == NULL_TREE)
	  return error_mark_node;

	if (explicitp == 2)
	  DECL_NONCONVERTING_P (decl) = 1;
	if (staticp == 1)
	  {
	    int invalid_static = 0;

	    /* Don't allow a static member function in a class, and forbid
	       declaring main to be static.  */
	    if (TREE_CODE (type) == METHOD_TYPE)
	      {
		permerror (input_location, "cannot declare member function %qD to have "
			   "static linkage", decl);
		invalid_static = 1;
	      }
	    else if (current_function_decl)
	      {
		/* 7.1.1: There can be no static function declarations within a
		   block.  */
		error_at (declspecs->locations[ds_storage_class],
			  "cannot declare static function inside another function");
		invalid_static = 1;
	      }

	    if (invalid_static)
	      {
		staticp = 0;
		storage_class = sc_none;
	      }
	  }
	if (declspecs->explicit_specifier)
	  store_explicit_specifier (decl, declspecs->explicit_specifier);
      }
    else
      {
	/* It's a variable.  */

	/* An uninitialized decl with `extern' is a reference.  */
	decl = grokvardecl (type, dname, unqualified_id,
			    declspecs,
			    initialized,
			    type_quals,
			    inlinep,
			    concept_p,
			    template_count,
			    ctype ? ctype : in_namespace,
			    id_loc);
	if (decl == NULL_TREE)
	  return error_mark_node;

	bad_specifiers (decl, BSP_VAR, virtualp,
			memfn_quals != TYPE_UNQUALIFIED,
			inlinep, friendp, raises != NULL_TREE,
			declspecs->locations);

	if (ctype)
	  {
	    DECL_CONTEXT (decl) = ctype;
	    if (staticp == 1)
	      {
		permerror (declspecs->locations[ds_storage_class],
			   "%<static%> may not be used when defining "
			   "(as opposed to declaring) a static data member");
		staticp = 0;
		storage_class = sc_none;
	      }
	    if (storage_class == sc_register && TREE_STATIC (decl))
	      {
		error ("static member %qD declared %<register%>", decl);
		storage_class = sc_none;
	      }
	    if (storage_class == sc_extern && pedantic)
	      {
		pedwarn (input_location, OPT_Wpedantic, 
			 "cannot explicitly declare member %q#D to have "
			 "extern linkage", decl);
		storage_class = sc_none;
	      }
	  }
	else if (constexpr_p && DECL_EXTERNAL (decl))
	  {
	    error_at (DECL_SOURCE_LOCATION (decl),
		      "declaration of %<constexpr%> variable %qD "
		      "is not a definition", decl);
	    constexpr_p = false;
	  }
	if (consteval_p)
	  {
	    error_at (DECL_SOURCE_LOCATION (decl),
		      "a variable cannot be declared %<consteval%>");
	    consteval_p = false;
	  }

	if (inlinep)
	  mark_inline_variable (decl, declspecs->locations[ds_inline]);
	if (innermost_code == cdk_decomp)
	  {
	    gcc_assert (declarator && declarator->kind == cdk_decomp);
	    DECL_SOURCE_LOCATION (decl) = id_loc;
	    DECL_ARTIFICIAL (decl) = 1;
	    fit_decomposition_lang_decl (decl, NULL_TREE);
	  }
      }

    if (VAR_P (decl) && !initialized)
      if (tree auto_node = type_uses_auto (type))
	if (!CLASS_PLACEHOLDER_TEMPLATE (auto_node))
	  {
	    location_t loc = declspecs->locations[ds_type_spec];
	    error_at (loc, "declaration of %q#D has no initializer", decl);
	    TREE_TYPE (decl) = error_mark_node;
	  }

    if (storage_class == sc_extern && initialized && !funcdef_flag)
      {
	if (toplevel_bindings_p ())
	  {
	    /* It's common practice (and completely valid) to have a const
	       be initialized and declared extern.  */
	    if (!(type_quals & TYPE_QUAL_CONST))
	      warning_at (DECL_SOURCE_LOCATION (decl), 0,
			  "%qs initialized and declared %<extern%>", name);
	  }
	else
	  {
	    error_at (DECL_SOURCE_LOCATION (decl),
		      "%qs has both %<extern%> and initializer", name);
	    return error_mark_node;
	  }
      }

    /* Record `register' declaration for warnings on &
       and in case doing stupid register allocation.  */

    if (storage_class == sc_register)
      {
	DECL_REGISTER (decl) = 1;
	/* Warn about register storage specifiers on PARM_DECLs.  */
	if (TREE_CODE (decl) == PARM_DECL)
	  {
	    if (cxx_dialect >= cxx17)
	      pedwarn (DECL_SOURCE_LOCATION (decl), OPT_Wregister,
		       "ISO C++17 does not allow %<register%> storage "
		       "class specifier");
	    else
	      warning_at (DECL_SOURCE_LOCATION (decl), OPT_Wregister,
			  "%<register%> storage class specifier used");
	  }
      }
    else if (storage_class == sc_extern)
      DECL_THIS_EXTERN (decl) = 1;
    else if (storage_class == sc_static)
      DECL_THIS_STATIC (decl) = 1;

    if (VAR_P (decl))
      {
	/* Set constexpr flag on vars (functions got it in grokfndecl).  */
	if (constexpr_p)
	  DECL_DECLARED_CONSTEXPR_P (decl) = true;
	/* And the constinit flag (which only applies to variables).  */
	else if (constinit_p)
	  DECL_DECLARED_CONSTINIT_P (decl) = true;
      }

    /* Record constancy and volatility on the DECL itself .  There's
       no need to do this when processing a template; we'll do this
       for the instantiated declaration based on the type of DECL.  */
    if (!processing_template_decl
	/* Don't do it for instantiated variable templates either,
	   cp_apply_type_quals_to_decl should have been called on it
	   already and might have been overridden in cp_finish_decl
	   if initializer needs runtime initialization.  */
	&& (!VAR_P (decl) || !DECL_TEMPLATE_INSTANTIATED (decl)))
      cp_apply_type_quals_to_decl (type_quals, decl);

    return decl;
  }
}

/* Subroutine of start_function.  Ensure that each of the parameter
   types (as listed in PARMS) is complete, as is required for a
   function definition.  */

static void
require_complete_types_for_parms (tree parms)
{
  for (; parms; parms = DECL_CHAIN (parms))
    {
      if (dependent_type_p (TREE_TYPE (parms)))
	continue;
      if (!VOID_TYPE_P (TREE_TYPE (parms))
	  && complete_type_or_else (TREE_TYPE (parms), parms))
	{
	  relayout_decl (parms);
	  DECL_ARG_TYPE (parms) = type_passed_as (TREE_TYPE (parms));

	  abstract_virtuals_error (parms, TREE_TYPE (parms));
	  maybe_warn_parm_abi (TREE_TYPE (parms),
			       DECL_SOURCE_LOCATION (parms));
	}
      else
	/* grokparms or complete_type_or_else will have already issued
	   an error.  */
	TREE_TYPE (parms) = error_mark_node;
    }
}

/* Returns nonzero if T is a local variable.  */

int
local_variable_p (const_tree t)
{
  if ((VAR_P (t)
       && (DECL_LOCAL_DECL_P (t)
	   || !DECL_CONTEXT (t)
	   || TREE_CODE (DECL_CONTEXT (t)) == FUNCTION_DECL))
      || (TREE_CODE (t) == PARM_DECL))
    return 1;

  return 0;
}

/* Like local_variable_p, but suitable for use as a tree-walking
   function.  */

static tree
local_variable_p_walkfn (tree *tp, int *walk_subtrees,
			 void * /*data*/)
{
  if (unevaluated_p (TREE_CODE (*tp)))
    {
      /* DR 2082 permits local variables in unevaluated contexts
	 within a default argument.  */
      *walk_subtrees = 0;
      return NULL_TREE;
    }

  if (local_variable_p (*tp)
      && (!DECL_ARTIFICIAL (*tp) || DECL_NAME (*tp) == this_identifier))
    return *tp;
  else if (TYPE_P (*tp))
    *walk_subtrees = 0;

  return NULL_TREE;
}

/* Check that ARG, which is a default-argument expression for a
   parameter DECL, is valid.  Returns ARG, or ERROR_MARK_NODE, if
   something goes wrong.  DECL may also be a _TYPE node, rather than a
   DECL, if there is no DECL available.  */

tree
check_default_argument (tree decl, tree arg, tsubst_flags_t complain)
{
  tree var;
  tree decl_type;

  if (TREE_CODE (arg) == DEFERRED_PARSE)
    /* We get a DEFERRED_PARSE when looking at an in-class declaration
       with a default argument.  Ignore the argument for now; we'll
       deal with it after the class is complete.  */
    return arg;

  if (TYPE_P (decl))
    {
      decl_type = decl;
      decl = NULL_TREE;
    }
  else
    decl_type = TREE_TYPE (decl);

  if (arg == error_mark_node
      || decl == error_mark_node
      || TREE_TYPE (arg) == error_mark_node
      || decl_type == error_mark_node)
    /* Something already went wrong.  There's no need to check
       further.  */
    return error_mark_node;

  /* [dcl.fct.default]

     A default argument expression is implicitly converted to the
     parameter type.  */
  ++cp_unevaluated_operand;
  /* Avoid digest_init clobbering the initializer.  */
  tree carg = BRACE_ENCLOSED_INITIALIZER_P (arg) ? unshare_expr (arg): arg;
  perform_implicit_conversion_flags (decl_type, carg, complain,
				     LOOKUP_IMPLICIT);
  --cp_unevaluated_operand;

  /* Avoid redundant -Wzero-as-null-pointer-constant warnings at
     the call sites.  */
  if (TYPE_PTR_OR_PTRMEM_P (decl_type)
      && null_ptr_cst_p (arg)
      /* Don't lose side-effects as in PR90473.  */
      && !TREE_SIDE_EFFECTS (arg))
    return nullptr_node;

  /* [dcl.fct.default]

     Local variables shall not be used in default argument
     expressions.

     The keyword `this' shall not be used in a default argument of a
     member function.  */
  var = cp_walk_tree_without_duplicates (&arg, local_variable_p_walkfn, NULL);
  if (var)
    {
      if (complain & tf_warning_or_error)
	{
	  if (DECL_NAME (var) == this_identifier)
	    permerror (input_location, "default argument %qE uses %qD",
		       arg, var);
	  else
	    error ("default argument %qE uses local variable %qD", arg, var);
	}
      return error_mark_node;
    }

  /* All is well.  */
  return arg;
}

/* Returns a deprecated type used within TYPE, or NULL_TREE if none.  */

static tree
type_is_deprecated (tree type)
{
  enum tree_code code;
  if (TREE_DEPRECATED (type))
    return type;
  if (TYPE_NAME (type))
    {
      if (TREE_DEPRECATED (TYPE_NAME (type)))
	return type;
      else
	{
	  cp_warn_deprecated_use_scopes (CP_DECL_CONTEXT (TYPE_NAME (type)));
	  return NULL_TREE;
	}
    }

  /* Do warn about using typedefs to a deprecated class.  */
  if (OVERLOAD_TYPE_P (type) && type != TYPE_MAIN_VARIANT (type))
    return type_is_deprecated (TYPE_MAIN_VARIANT (type));

  code = TREE_CODE (type);

  if (code == POINTER_TYPE || code == REFERENCE_TYPE
      || code == OFFSET_TYPE || code == FUNCTION_TYPE
      || code == METHOD_TYPE || code == ARRAY_TYPE)
    return type_is_deprecated (TREE_TYPE (type));

  if (TYPE_PTRMEMFUNC_P (type))
    return type_is_deprecated
      (TREE_TYPE (TREE_TYPE (TYPE_PTRMEMFUNC_FN_TYPE (type))));

  return NULL_TREE;
}

/* Returns an unavailable type used within TYPE, or NULL_TREE if none.  */

static tree
type_is_unavailable (tree type)
{
  enum tree_code code;
  if (TREE_UNAVAILABLE (type))
    return type;
  if (TYPE_NAME (type))
    {
      if (TREE_UNAVAILABLE (TYPE_NAME (type)))
	return type;
      else
	{
	  cp_warn_deprecated_use_scopes (CP_DECL_CONTEXT (TYPE_NAME (type)));
	  return NULL_TREE;
	}
    }

  /* Do warn about using typedefs to a deprecated class.  */
  if (OVERLOAD_TYPE_P (type) && type != TYPE_MAIN_VARIANT (type))
    return type_is_deprecated (TYPE_MAIN_VARIANT (type));

  code = TREE_CODE (type);

  if (code == POINTER_TYPE || code == REFERENCE_TYPE
      || code == OFFSET_TYPE || code == FUNCTION_TYPE
      || code == METHOD_TYPE || code == ARRAY_TYPE)
    return type_is_unavailable (TREE_TYPE (type));

  if (TYPE_PTRMEMFUNC_P (type))
    return type_is_unavailable
      (TREE_TYPE (TREE_TYPE (TYPE_PTRMEMFUNC_FN_TYPE (type))));

  return NULL_TREE;
}

/* Decode the list of parameter types for a function type.
   Given the list of things declared inside the parens,
   return a list of types.

   If this parameter does not end with an ellipsis, we append
   void_list_node.

   *PARMS is set to the chain of PARM_DECLs created.  */

tree
grokparms (tree parmlist, tree *parms)
{
  tree result = NULL_TREE;
  tree decls = NULL_TREE;
  tree parm;
  int any_error = 0;

  for (parm = parmlist; parm != NULL_TREE; parm = TREE_CHAIN (parm))
    {
      tree type = NULL_TREE;
      tree init = TREE_PURPOSE (parm);
      tree decl = TREE_VALUE (parm);

      if (parm == void_list_node || parm == explicit_void_list_node)
	break;

      if (! decl || TREE_TYPE (decl) == error_mark_node)
	{
	  any_error = 1;
	  continue;
	}

      type = TREE_TYPE (decl);
      if (VOID_TYPE_P (type))
	{
	  if (same_type_p (type, void_type_node)
	      && !init
	      && !DECL_NAME (decl) && !result
	      && TREE_CHAIN (parm) == void_list_node)
	    /* DR 577: A parameter list consisting of a single
	       unnamed parameter of non-dependent type 'void'.  */
	    break;
	  else if (cv_qualified_p (type))
	    error_at (DECL_SOURCE_LOCATION (decl),
		      "invalid use of cv-qualified type %qT in "
		      "parameter declaration", type);
	  else
	    error_at (DECL_SOURCE_LOCATION (decl),
		      "invalid use of type %<void%> in parameter "
		      "declaration");
	  /* It's not a good idea to actually create parameters of
	     type `void'; other parts of the compiler assume that a
	     void type terminates the parameter list.  */
	  type = error_mark_node;
	  TREE_TYPE (decl) = error_mark_node;
	}

      if (type != error_mark_node)
	{
	  if (deprecated_state != UNAVAILABLE_DEPRECATED_SUPPRESS)
	    {
	      tree unavailtype = type_is_unavailable (type);
	      if (unavailtype)
		cp_handle_deprecated_or_unavailable (unavailtype);
	    }
	  if (deprecated_state != DEPRECATED_SUPPRESS
	      && deprecated_state != UNAVAILABLE_DEPRECATED_SUPPRESS)
	    {
	      tree deptype = type_is_deprecated (type);
	      if (deptype)
		cp_handle_deprecated_or_unavailable (deptype);
	    }

	  /* [dcl.fct] "A parameter with volatile-qualified type is
	     deprecated."  */
	  if (CP_TYPE_VOLATILE_P (type))
	    warning_at (DECL_SOURCE_LOCATION (decl), OPT_Wvolatile,
			"%<volatile%>-qualified parameter is "
			"deprecated");

	  /* Top-level qualifiers on the parameters are
	     ignored for function types.  */
	  type = cp_build_qualified_type (type, 0);
	  if (TREE_CODE (type) == METHOD_TYPE)
	    {
	      error ("parameter %qD invalidly declared method type", decl);
	      type = build_pointer_type (type);
	      TREE_TYPE (decl) = type;
	    }
	  else if (cxx_dialect < cxx17 && INDIRECT_TYPE_P (type))
	    {
	      /* Before C++17 DR 393:
		 [dcl.fct]/6, parameter types cannot contain pointers
		 (references) to arrays of unknown bound.  */
	      tree t = TREE_TYPE (type);
	      int ptr = TYPE_PTR_P (type);

	      while (1)
		{
		  if (TYPE_PTR_P (t))
		    ptr = 1;
		  else if (TREE_CODE (t) != ARRAY_TYPE)
		    break;
		  else if (!TYPE_DOMAIN (t))
		    break;
		  t = TREE_TYPE (t);
		}
	      if (TREE_CODE (t) == ARRAY_TYPE)
		pedwarn (DECL_SOURCE_LOCATION (decl), OPT_Wpedantic,
			 ptr
			 ? G_("parameter %qD includes pointer to array of "
			      "unknown bound %qT")
			 : G_("parameter %qD includes reference to array of "
			      "unknown bound %qT"),
			 decl, t);
	    }

	  if (init && !processing_template_decl)
	    init = check_default_argument (decl, init, tf_warning_or_error);
	}

      DECL_CHAIN (decl) = decls;
      decls = decl;
      result = tree_cons (init, type, result);
    }
  decls = nreverse (decls);
  result = nreverse (result);
  if (parm)
    result = chainon (result, void_list_node);
  *parms = decls;
  if (any_error)
    result = NULL_TREE;

  if (any_error)
    /* We had parm errors, recover by giving the function (...) type.  */
    result = NULL_TREE;

  return result;
}


/* D is a constructor or overloaded `operator='.

   Let T be the class in which D is declared. Then, this function
   returns:

   -1 if D's is an ill-formed constructor or copy assignment operator
      whose first parameter is of type `T'.
   0  if D is not a copy constructor or copy assignment
      operator.
   1  if D is a copy constructor or copy assignment operator whose
      first parameter is a reference to non-const qualified T.
   2  if D is a copy constructor or copy assignment operator whose
      first parameter is a reference to const qualified T.

   This function can be used as a predicate. Positive values indicate
   a copy constructor and nonzero values indicate a copy assignment
   operator.  */

int
copy_fn_p (const_tree d)
{
  tree args;
  tree arg_type;
  int result = 1;

  gcc_assert (DECL_FUNCTION_MEMBER_P (d));

  if (TREE_CODE (d) == TEMPLATE_DECL
      || (DECL_TEMPLATE_INFO (d)
	  && DECL_MEMBER_TEMPLATE_P (DECL_TI_TEMPLATE (d))))
    /* Instantiations of template member functions are never copy
       functions.  Note that member functions of templated classes are
       represented as template functions internally, and we must
       accept those as copy functions.  */
    return 0;

  if (!DECL_CONSTRUCTOR_P (d)
      && DECL_NAME (d) != assign_op_identifier)
    return 0;

  args = FUNCTION_FIRST_USER_PARMTYPE (d);
  if (!args)
    return 0;

  arg_type = TREE_VALUE (args);
  if (arg_type == error_mark_node)
    return 0;

  if (TYPE_MAIN_VARIANT (arg_type) == DECL_CONTEXT (d))
    {
      /* Pass by value copy assignment operator.  */
      result = -1;
    }
  else if (TYPE_REF_P (arg_type)
	   && !TYPE_REF_IS_RVALUE (arg_type)
	   && TYPE_MAIN_VARIANT (TREE_TYPE (arg_type)) == DECL_CONTEXT (d))
    {
      if (CP_TYPE_CONST_P (TREE_TYPE (arg_type)))
	result = 2;
    }
  else
    return 0;

  args = TREE_CHAIN (args);

  if (args && args != void_list_node && !TREE_PURPOSE (args))
    /* There are more non-optional args.  */
    return 0;

  return result;
}

/* D is a constructor or overloaded `operator='.

   Let T be the class in which D is declared. Then, this function
   returns true when D is a move constructor or move assignment
   operator, false otherwise.  */

bool
move_fn_p (const_tree d)
{
  if (cxx_dialect == cxx98)
    /* There are no move constructors if we are in C++98 mode.  */
    return false;

  if (TREE_CODE (d) == TEMPLATE_DECL
      || (DECL_TEMPLATE_INFO (d)
         && DECL_MEMBER_TEMPLATE_P (DECL_TI_TEMPLATE (d))))
    /* Instantiations of template member functions are never move
       functions.  Note that member functions of templated classes are
       represented as template functions internally, and we must
       accept those as move functions.  */
    return 0;

  return move_signature_fn_p (d);
}

/* D is a constructor or overloaded `operator='.

   Then, this function returns true when D has the same signature as a move
   constructor or move assignment operator (because either it is such a
   ctor/op= or it is a template specialization with the same signature),
   false otherwise.  */

bool
move_signature_fn_p (const_tree d)
{
  tree args;
  tree arg_type;
  bool result = false;

  if (!DECL_CONSTRUCTOR_P (d)
      && DECL_NAME (d) != assign_op_identifier)
    return 0;

  args = FUNCTION_FIRST_USER_PARMTYPE (d);
  if (!args)
    return 0;

  arg_type = TREE_VALUE (args);
  if (arg_type == error_mark_node)
    return 0;

  if (TYPE_REF_P (arg_type)
      && TYPE_REF_IS_RVALUE (arg_type)
      && same_type_p (TYPE_MAIN_VARIANT (TREE_TYPE (arg_type)),
                      DECL_CONTEXT (d)))
    result = true;

  args = TREE_CHAIN (args);

  if (args && args != void_list_node && !TREE_PURPOSE (args))
    /* There are more non-optional args.  */
    return false;

  return result;
}

/* Remember any special properties of member function DECL.  */

void
grok_special_member_properties (tree decl)
{
  tree class_type;

  if (TREE_CODE (decl) == USING_DECL
      || !DECL_NONSTATIC_MEMBER_FUNCTION_P (decl))
    return;

  class_type = DECL_CONTEXT (decl);
  if (IDENTIFIER_CTOR_P (DECL_NAME (decl)))
    {
      int ctor = copy_fn_p (decl);

      if (!DECL_ARTIFICIAL (decl))
	TYPE_HAS_USER_CONSTRUCTOR (class_type) = 1;

      if (ctor > 0)
	{
	  /* [class.copy]

	     A non-template constructor for class X is a copy
	     constructor if its first parameter is of type X&, const
	     X&, volatile X& or const volatile X&, and either there
	     are no other parameters or else all other parameters have
	     default arguments.  */
	  TYPE_HAS_COPY_CTOR (class_type) = 1;
	  if (ctor > 1)
	    TYPE_HAS_CONST_COPY_CTOR (class_type) = 1;
	}

      if (sufficient_parms_p (FUNCTION_FIRST_USER_PARMTYPE (decl)))
	TYPE_HAS_DEFAULT_CONSTRUCTOR (class_type) = 1;

      if (is_list_ctor (decl))
	TYPE_HAS_LIST_CTOR (class_type) = 1;

      if (maybe_constexpr_fn (decl)
	  && !ctor && !move_fn_p (decl))
	TYPE_HAS_CONSTEXPR_CTOR (class_type) = 1;
    }
  else if (DECL_NAME (decl) == assign_op_identifier)
    {
      /* [class.copy]

	 A non-template assignment operator for class X is a copy
	 assignment operator if its parameter is of type X, X&, const
	 X&, volatile X& or const volatile X&.  */

      int assop = copy_fn_p (decl);

      if (assop)
	{
	  TYPE_HAS_COPY_ASSIGN (class_type) = 1;
	  if (assop != 1)
	    TYPE_HAS_CONST_COPY_ASSIGN (class_type) = 1;
	}
    }
  else if (IDENTIFIER_CONV_OP_P (DECL_NAME (decl)))
    TYPE_HAS_CONVERSION (class_type) = true;
  
  /* Destructors are handled in check_methods.  */
}

/* Check a constructor DECL has the correct form.  Complains
   if the class has a constructor of the form X(X).  */

bool
grok_ctor_properties (const_tree ctype, const_tree decl)
{
  int ctor_parm = copy_fn_p (decl);

  if (ctor_parm < 0)
    {
      /* [class.copy]

	 A declaration of a constructor for a class X is ill-formed if
	 its first parameter is of type (optionally cv-qualified) X
	 and either there are no other parameters or else all other
	 parameters have default arguments.

	 We *don't* complain about member template instantiations that
	 have this form, though; they can occur as we try to decide
	 what constructor to use during overload resolution.  Since
	 overload resolution will never prefer such a constructor to
	 the non-template copy constructor (which is either explicitly
	 or implicitly defined), there's no need to worry about their
	 existence.  Theoretically, they should never even be
	 instantiated, but that's hard to forestall.  */
      error_at (DECL_SOURCE_LOCATION (decl),
		"invalid constructor; you probably meant %<%T (const %T&)%>",
		ctype, ctype);
      return false;
    }

  return true;
}

/* DECL is a declaration for an overloaded or conversion operator.  If
   COMPLAIN is true, errors are issued for invalid declarations.  */

bool
grok_op_properties (tree decl, bool complain)
{
  tree argtypes = TYPE_ARG_TYPES (TREE_TYPE (decl));
  bool methodp = TREE_CODE (TREE_TYPE (decl)) == METHOD_TYPE;
  tree name = DECL_NAME (decl);
  location_t loc = DECL_SOURCE_LOCATION (decl);

  tree class_type = DECL_CONTEXT (decl);
  if (class_type && !CLASS_TYPE_P (class_type))
    class_type = NULL_TREE;

  tree_code operator_code;
  unsigned op_flags;
  if (IDENTIFIER_CONV_OP_P (name))
    {
      /* Conversion operators are TYPE_EXPR for the purposes of this
	 function.  */
      operator_code = TYPE_EXPR;
      op_flags = OVL_OP_FLAG_UNARY;
    }
  else
    {
      const ovl_op_info_t *ovl_op = IDENTIFIER_OVL_OP_INFO (name);

      operator_code = ovl_op->tree_code;
      op_flags = ovl_op->flags;
      gcc_checking_assert (operator_code != ERROR_MARK);
      DECL_OVERLOADED_OPERATOR_CODE_RAW (decl) = ovl_op->ovl_op_code;
    }

  if (op_flags & OVL_OP_FLAG_ALLOC)
    {
      /* operator new and operator delete are quite special.  */
      if (class_type)
	switch (op_flags)
	  {
	  case OVL_OP_FLAG_ALLOC:
	    TYPE_HAS_NEW_OPERATOR (class_type) = 1;
	    break;

	  case OVL_OP_FLAG_ALLOC | OVL_OP_FLAG_DELETE:
	    TYPE_GETS_DELETE (class_type) |= 1;
	    break;

	  case OVL_OP_FLAG_ALLOC | OVL_OP_FLAG_VEC:
	    TYPE_HAS_ARRAY_NEW_OPERATOR (class_type) = 1;
	    break;

	  case OVL_OP_FLAG_ALLOC | OVL_OP_FLAG_DELETE | OVL_OP_FLAG_VEC:
	    TYPE_GETS_DELETE (class_type) |= 2;
	    break;

	  default:
	    gcc_unreachable ();
	  }

      /* [basic.std.dynamic.allocation]/1:

	 A program is ill-formed if an allocation function is declared
	 in a namespace scope other than global scope or declared
	 static in global scope.

	 The same also holds true for deallocation functions.  */
      if (DECL_NAMESPACE_SCOPE_P (decl))
	{
	  if (CP_DECL_CONTEXT (decl) != global_namespace)
	    {
	      error_at (loc, "%qD may not be declared within a namespace",
			decl);
	      return false;
	    }

	  if (!TREE_PUBLIC (decl))
	    {
	      error_at (loc, "%qD may not be declared as static", decl);
	      return false;
	    }
	}

      if (op_flags & OVL_OP_FLAG_DELETE)
	{
	  DECL_SET_IS_OPERATOR_DELETE (decl, true);
	  coerce_delete_type (decl, loc);
	}
      else
	{
	  DECL_SET_IS_OPERATOR_NEW (decl, true);
	  TREE_TYPE (decl) = coerce_new_type (TREE_TYPE (decl), loc);
	}

      return true;
    }

  /* An operator function must either be a non-static member function
     or have at least one parameter of a class, a reference to a class,
     an enumeration, or a reference to an enumeration.  13.4.0.6 */
  if (! methodp || DECL_STATIC_FUNCTION_P (decl))
    {
      if (operator_code == TYPE_EXPR
	  || operator_code == CALL_EXPR
	  || operator_code == COMPONENT_REF
	  || operator_code == ARRAY_REF
	  || operator_code == NOP_EXPR)
	{
	  error_at (loc, "%qD must be a non-static member function", decl);
	  return false;
	}

      if (DECL_STATIC_FUNCTION_P (decl))
	{
	  error_at (loc, "%qD must be either a non-static member "
		    "function or a non-member function", decl);
	  return false;
	}

      for (tree arg = argtypes; ; arg = TREE_CHAIN (arg))
	{
	  if (!arg || arg == void_list_node)
	    {
	      if (complain)
		error_at(loc, "%qD must have an argument of class or "
			 "enumerated type", decl);
	      return false;
	    }
      
	  tree type = non_reference (TREE_VALUE (arg));
	  if (type == error_mark_node)
	    return false;
	  
	  /* MAYBE_CLASS_TYPE_P, rather than CLASS_TYPE_P, is used
	     because these checks are performed even on template
	     functions.  */
	  if (MAYBE_CLASS_TYPE_P (type)
	      || TREE_CODE (type) == ENUMERAL_TYPE)
	    break;
	}
    }

  if (operator_code == CALL_EXPR)
    /* There are no further restrictions on the arguments to an overloaded
       "operator ()".  */
    return true;

  if (operator_code == COND_EXPR)
    {
      /* 13.4.0.3 */
      error_at (loc, "ISO C++ prohibits overloading %<operator ?:%>");
      return false;
    }

  /* Count the number of arguments and check for ellipsis.  */
  int arity = 0;
  for (tree arg = argtypes; arg != void_list_node; arg = TREE_CHAIN (arg))
    {
      if (!arg)
	{
	  /* Variadic.  */
	  if (operator_code == ARRAY_REF && cxx_dialect >= cxx23)
	    break;

	  error_at (loc, "%qD must not have variable number of arguments",
		    decl);
	  return false;
	}
      ++arity;
    }

  /* Verify correct number of arguments.  */
  switch (op_flags)
    {
    case OVL_OP_FLAG_AMBIARY:
      if (arity == 1)
	{
	  /* We have a unary instance of an ambi-ary op.  Remap to the
	     unary one.  */
	  unsigned alt = ovl_op_alternate[ovl_op_mapping [operator_code]];
	  const ovl_op_info_t *ovl_op = &ovl_op_info[false][alt];
	  gcc_checking_assert (ovl_op->flags == OVL_OP_FLAG_UNARY);
	  operator_code = ovl_op->tree_code;
	  DECL_OVERLOADED_OPERATOR_CODE_RAW (decl) = ovl_op->ovl_op_code;
	}
      else if (arity != 2)
	{
	  /* This was an ambiguous operator but is invalid. */
	  error_at (loc,
		    methodp
		    ? G_("%qD must have either zero or one argument")
		    : G_("%qD must have either one or two arguments"), decl);
	  return false;
	}
      else if ((operator_code == POSTINCREMENT_EXPR
		|| operator_code == POSTDECREMENT_EXPR)
	       && ! processing_template_decl
	       /* x++ and x--'s second argument must be an int.  */
	       && ! same_type_p (TREE_VALUE (TREE_CHAIN (argtypes)),
				 integer_type_node))
	{
	  error_at (loc,
		    methodp
		    ? G_("postfix %qD must have %<int%> as its argument")
		    : G_("postfix %qD must have %<int%> as its second argument"),
		    decl);
	  return false;
	}
      break;

    case OVL_OP_FLAG_UNARY:
      if (arity != 1)
	{
	  error_at (loc,
		    methodp
		    ? G_("%qD must have no arguments")
		    : G_("%qD must have exactly one argument"), decl);
	  return false;
	}
      break;

    case OVL_OP_FLAG_BINARY:
      if (arity != 2)
	{
	  if (operator_code == ARRAY_REF && cxx_dialect >= cxx23)
	    break;
	  error_at (loc,
		    methodp
		    ? G_("%qD must have exactly one argument")
		    : G_("%qD must have exactly two arguments"), decl);
	  return false;
	}
      break;

    default:
      gcc_unreachable ();
    }

  /* There can be no default arguments.  */
  for (tree arg = argtypes; arg && arg != void_list_node;
       arg = TREE_CHAIN (arg))
    if (TREE_PURPOSE (arg))
      {
	TREE_PURPOSE (arg) = NULL_TREE;
	error_at (loc, "%qD cannot have default arguments", decl);
	return false;
      }

  /* At this point the declaration is well-formed.  It may not be
     sensible though.  */

  /* Check member function warnings only on the in-class declaration.
     There's no point warning on an out-of-class definition.  */
  if (class_type && class_type != current_class_type)
    return true;

  /* Warn about conversion operators that will never be used.  */
  if (IDENTIFIER_CONV_OP_P (name)
      && ! DECL_TEMPLATE_INFO (decl)
      && warn_class_conversion)
    {
      tree t = TREE_TYPE (name);
      int ref = TYPE_REF_P (t);

      if (ref)
	t = TYPE_MAIN_VARIANT (TREE_TYPE (t));

      if (VOID_TYPE_P (t))
	warning_at (loc, OPT_Wclass_conversion, "converting %qT to %<void%> "
		    "will never use a type conversion operator", class_type);
      else if (class_type)
	{
	  if (same_type_ignoring_top_level_qualifiers_p (t, class_type))
	    warning_at (loc, OPT_Wclass_conversion,
			ref
			? G_("converting %qT to a reference to the same type "
			     "will never use a type conversion operator")
			: G_("converting %qT to the same type "
			     "will never use a type conversion operator"),
			class_type);
	  /* Don't force t to be complete here.  */
	  else if (MAYBE_CLASS_TYPE_P (t)
		   && COMPLETE_TYPE_P (t)
		   && DERIVED_FROM_P (t, class_type))
	    warning_at (loc, OPT_Wclass_conversion,
			ref
			? G_("converting %qT to a reference to a base class "
			     "%qT will never use a type conversion operator")
			: G_("converting %qT to a base class %qT "
			     "will never use a type conversion operator"),
			class_type, t);
	}
    }

  if (!warn_ecpp)
    return true;

  /* Effective C++ rules below.  */

  /* More Effective C++ rule 7.  */
  if (operator_code == TRUTH_ANDIF_EXPR
      || operator_code == TRUTH_ORIF_EXPR
      || operator_code == COMPOUND_EXPR)
    warning_at (loc, OPT_Weffc__,
		"user-defined %qD always evaluates both arguments", decl);
  
  /* More Effective C++ rule 6.  */
  if (operator_code == POSTINCREMENT_EXPR
      || operator_code == POSTDECREMENT_EXPR
      || operator_code == PREINCREMENT_EXPR
      || operator_code == PREDECREMENT_EXPR)
    {
      tree arg = TREE_VALUE (argtypes);
      tree ret = TREE_TYPE (TREE_TYPE (decl));
      if (methodp || TYPE_REF_P (arg))
	arg = TREE_TYPE (arg);
      arg = TYPE_MAIN_VARIANT (arg);

      if (operator_code == PREINCREMENT_EXPR
	  || operator_code == PREDECREMENT_EXPR)
	{
	  if (!TYPE_REF_P (ret)
	      || !same_type_p (TYPE_MAIN_VARIANT (TREE_TYPE (ret)), arg))
	    warning_at (loc, OPT_Weffc__, "prefix %qD should return %qT", decl,
			build_reference_type (arg));
	}
      else
	{
	  if (!same_type_p (TYPE_MAIN_VARIANT (ret), arg))
	    warning_at (loc, OPT_Weffc__,
			"postfix %qD should return %qT", decl, arg);
	}
    }

  /* Effective C++ rule 23.  */
  if (!DECL_ASSIGNMENT_OPERATOR_P (decl)
      && (operator_code == PLUS_EXPR
	  || operator_code == MINUS_EXPR
	  || operator_code == TRUNC_DIV_EXPR
	  || operator_code == MULT_EXPR
	  || operator_code == TRUNC_MOD_EXPR)
      && TYPE_REF_P (TREE_TYPE (TREE_TYPE (decl))))
    warning_at (loc, OPT_Weffc__, "%qD should return by value", decl);

  return true;
}

/* Return a string giving the keyword associate with CODE.  */

static const char *
tag_name (enum tag_types code)
{
  switch (code)
    {
    case record_type:
      return "struct";
    case class_type:
      return "class";
    case union_type:
      return "union";
    case enum_type:
      return "enum";
    case typename_type:
      return "typename";
    default:
      gcc_unreachable ();
    }
}

/* Name lookup in an elaborated-type-specifier (after the keyword
   indicated by TAG_CODE) has found the TYPE_DECL DECL.  If the
   elaborated-type-specifier is invalid, issue a diagnostic and return
   error_mark_node; otherwise, return the *_TYPE to which it referred.
   If ALLOW_TEMPLATE_P is true, TYPE may be a class template.  */

tree
check_elaborated_type_specifier (enum tag_types tag_code,
				 tree decl,
				 bool allow_template_p)
{
  tree type;

  /* In the case of:

       struct S { struct S *p; };

     name lookup will find the TYPE_DECL for the implicit "S::S"
     typedef.  Adjust for that here.  */
  if (DECL_SELF_REFERENCE_P (decl))
    decl = TYPE_NAME (TREE_TYPE (decl));

  type = TREE_TYPE (decl);

  /* Check TEMPLATE_TYPE_PARM first because DECL_IMPLICIT_TYPEDEF_P
     is false for this case as well.  */
  if (TREE_CODE (type) == TEMPLATE_TYPE_PARM)
    {
      error ("using template type parameter %qT after %qs",
	     type, tag_name (tag_code));
      return error_mark_node;
    }
  /* Accept template template parameters.  */
  else if (allow_template_p
	   && (TREE_CODE (type) == BOUND_TEMPLATE_TEMPLATE_PARM
	       || TREE_CODE (type) == TEMPLATE_TEMPLATE_PARM))
    ;
  /*   [dcl.type.elab]

       If the identifier resolves to a typedef-name or the
       simple-template-id resolves to an alias template
       specialization, the elaborated-type-specifier is ill-formed.

     In other words, the only legitimate declaration to use in the
     elaborated type specifier is the implicit typedef created when
     the type is declared.  */
  else if (!DECL_IMPLICIT_TYPEDEF_P (decl)
	   && !DECL_SELF_REFERENCE_P (decl)
	   && tag_code != typename_type)
    {
      if (alias_template_specialization_p (type, nt_opaque))
	error ("using alias template specialization %qT after %qs",
	       type, tag_name (tag_code));
      else
	error ("using typedef-name %qD after %qs", decl, tag_name (tag_code));
      inform (DECL_SOURCE_LOCATION (decl),
	      "%qD has a previous declaration here", decl);
      return error_mark_node;
    }
  else if (TREE_CODE (type) != RECORD_TYPE
	   && TREE_CODE (type) != UNION_TYPE
	   && tag_code != enum_type
	   && tag_code != typename_type)
    {
      error ("%qT referred to as %qs", type, tag_name (tag_code));
      inform (location_of (type), "%qT has a previous declaration here", type);
      return error_mark_node;
    }
  else if (TREE_CODE (type) != ENUMERAL_TYPE
	   && tag_code == enum_type)
    {
      error ("%qT referred to as enum", type);
      inform (location_of (type), "%qT has a previous declaration here", type);
      return error_mark_node;
    }
  else if (!allow_template_p
	   && TREE_CODE (type) == RECORD_TYPE
	   && CLASSTYPE_IS_TEMPLATE (type))
    {
      /* If a class template appears as elaborated type specifier
	 without a template header such as:

	   template <class T> class C {};
	   void f(class C);		// No template header here

	 then the required template argument is missing.  */
      error ("template argument required for %<%s %T%>",
	     tag_name (tag_code),
	     DECL_NAME (CLASSTYPE_TI_TEMPLATE (type)));
      return error_mark_node;
    }

  return type;
}

/* Lookup NAME of an elaborated type specifier according to SCOPE and
   issue diagnostics if necessary.  Return *_TYPE node upon success,
   NULL_TREE when the NAME is not found, and ERROR_MARK_NODE for type
   error.  */

static tree
lookup_and_check_tag (enum tag_types tag_code, tree name,
		      TAG_how how, bool template_header_p)
{
  tree decl;
  if (how == TAG_how::GLOBAL)
    {
      /* First try ordinary name lookup, ignoring hidden class name
	 injected via friend declaration.  */
      decl = lookup_name (name, LOOK_want::TYPE);
      decl = strip_using_decl (decl);
      /* If that fails, the name will be placed in the smallest
	 non-class, non-function-prototype scope according to 3.3.1/5.
	 We may already have a hidden name declared as friend in this
	 scope.  So lookup again but not ignoring hidden names.
	 If we find one, that name will be made visible rather than
	 creating a new tag.  */
      if (!decl)
	decl = lookup_elaborated_type (name, TAG_how::INNERMOST_NON_CLASS);
    }
  else
    decl = lookup_elaborated_type (name, how);

  if (!decl)
    /* We found nothing.  */
    return NULL_TREE;

  if (TREE_CODE (decl) == TREE_LIST)
    {
      error ("reference to %qD is ambiguous", name);
      print_candidates (decl);
      return error_mark_node;
    }

  if (DECL_CLASS_TEMPLATE_P (decl)
      && !template_header_p
      && how == TAG_how::CURRENT_ONLY)
    {
      error ("class template %qD redeclared as non-template", name);
      inform (location_of (decl), "previous declaration here");
      CLASSTYPE_ERRONEOUS (TREE_TYPE (decl)) = true;
      return error_mark_node;
    }

  if (DECL_CLASS_TEMPLATE_P (decl)
      /* If scope is TAG_how::CURRENT_ONLY we're defining a class,
	 so ignore a template template parameter.  */
      || (how != TAG_how::CURRENT_ONLY && DECL_TEMPLATE_TEMPLATE_PARM_P (decl)))
    decl = DECL_TEMPLATE_RESULT (decl);

  if (TREE_CODE (decl) != TYPE_DECL)
    /* Found not-a-type.  */
    return NULL_TREE;
  
  /* Look for invalid nested type:
     class C {
     class C {};
     };  */
  if (how == TAG_how::CURRENT_ONLY && DECL_SELF_REFERENCE_P (decl))
    {
      error ("%qD has the same name as the class in which it is "
	     "declared", decl);
      return error_mark_node;
    }

  /* Two cases we need to consider when deciding if a class
     template is allowed as an elaborated type specifier:
     1. It is a self reference to its own class.
     2. It comes with a template header.

     For example:

     template <class T> class C {
       class C *c1;		// DECL_SELF_REFERENCE_P is true
       class D;
     };
     template <class U> class C; // template_header_p is true
     template <class T> class C<T>::D {
       class C *c2;		// DECL_SELF_REFERENCE_P is true
     };  */

  tree t = check_elaborated_type_specifier (tag_code, decl,
					    template_header_p
					    | DECL_SELF_REFERENCE_P (decl));
  if (template_header_p && t && CLASS_TYPE_P (t)
      && (!CLASSTYPE_TEMPLATE_INFO (t)
	  || (!PRIMARY_TEMPLATE_P (CLASSTYPE_TI_TEMPLATE (t)))))
    {
      error ("%qT is not a template", t);
      inform (location_of (t), "previous declaration here");
      if (TYPE_CLASS_SCOPE_P (t)
	  && CLASSTYPE_TEMPLATE_INFO (TYPE_CONTEXT (t)))
	inform (input_location,
		"perhaps you want to explicitly add %<%T::%>",
		TYPE_CONTEXT (t));
      return error_mark_node;
    }

  return t;
}

/* Get the struct, enum or union (TAG_CODE says which) with tag NAME.
   Define the tag as a forward-reference if it is not defined.

   If a declaration is given, process it here, and report an error if
   multiple declarations are not identical.

   SCOPE is TS_CURRENT when this is also a definition.  Only look in
   the current frame for the name (since C++ allows new names in any
   scope.)  It is TS_WITHIN_ENCLOSING_NON_CLASS if this is a friend
   declaration.  Only look beginning from the current scope outward up
   till the nearest non-class scope.  Otherwise it is TS_GLOBAL.

   TEMPLATE_HEADER_P is true when this declaration is preceded by
   a set of template parameters.  */

tree
xref_tag (enum tag_types tag_code, tree name,
	  TAG_how how, bool template_header_p)
{
  enum tree_code code;
  tree context = NULL_TREE;

  auto_cond_timevar tv (TV_NAME_LOOKUP);

  gcc_assert (identifier_p (name));

  switch (tag_code)
    {
    case record_type:
    case class_type:
      code = RECORD_TYPE;
      break;
    case union_type:
      code = UNION_TYPE;
      break;
    case enum_type:
      code = ENUMERAL_TYPE;
      break;
    default:
      gcc_unreachable ();
    }

  /* In case of anonymous name, xref_tag is only called to
     make type node and push name.  Name lookup is not required.  */
  tree t = NULL_TREE;
  if (!IDENTIFIER_ANON_P (name))
    t = lookup_and_check_tag  (tag_code, name, how, template_header_p);

  if (t == error_mark_node)
    return error_mark_node;

  if (how != TAG_how::CURRENT_ONLY && t && current_class_type
      && template_class_depth (current_class_type)
      && template_header_p)
    {
      if (TREE_CODE (t) == TEMPLATE_TEMPLATE_PARM)
	return t;

      /* Since HOW is not TAG_how::CURRENT_ONLY, we are not looking at
	 a definition of this tag.  Since, in addition, we are
	 currently processing a (member) template declaration of a
	 template class, we must be very careful; consider:

	   template <class X> struct S1

	   template <class U> struct S2
	   {
	     template <class V> friend struct S1;
	   };

	 Here, the S2::S1 declaration should not be confused with the
	 outer declaration.  In particular, the inner version should
	 have a template parameter of level 2, not level 1.

	 On the other hand, when presented with:

	   template <class T> struct S1
	   {
	     template <class U> struct S2 {};
	     template <class U> friend struct S2;
	   };

	 the friend must find S1::S2 eventually.  We accomplish this
	 by making sure that the new type we create to represent this
	 declaration has the right TYPE_CONTEXT.  */
      context = TYPE_CONTEXT (t);
      t = NULL_TREE;
    }

  if (! t)
    {
      /* If no such tag is yet defined, create a forward-reference node
	 and record it as the "definition".
	 When a real declaration of this type is found,
	 the forward-reference will be altered into a real type.  */
      if (code == ENUMERAL_TYPE)
	{
	  error ("use of enum %q#D without previous declaration", name);
	  return error_mark_node;
	}

      t = make_class_type (code);
      TYPE_CONTEXT (t) = context;
      if (IDENTIFIER_LAMBDA_P (name))
	/* Mark it as a lambda type right now.  Our caller will
	   correct the value.  */
	CLASSTYPE_LAMBDA_EXPR (t) = error_mark_node;
      t = pushtag (name, t, how);
    }
  else
    {
      if (template_header_p && MAYBE_CLASS_TYPE_P (t))
        {
          /* Check that we aren't trying to overload a class with different
             constraints.  */
          tree constr = NULL_TREE;
          if (current_template_parms)
            {
              tree reqs = TEMPLATE_PARMS_CONSTRAINTS (current_template_parms);
              constr = build_constraints (reqs, NULL_TREE);
            }
	  if (!redeclare_class_template (t, current_template_parms, constr))
	    return error_mark_node;
        }
      else if (!processing_template_decl
	       && CLASS_TYPE_P (t)
	       && CLASSTYPE_IS_TEMPLATE (t))
	{
	  error ("redeclaration of %qT as a non-template", t);
	  inform (location_of (t), "previous declaration %qD", t);
	  return error_mark_node;
	}

      if (modules_p ()
	  && how == TAG_how::CURRENT_ONLY)
	{
	  tree decl = TYPE_NAME (t);
	  if (!module_may_redeclare (decl))
	    {
	      error ("cannot declare %qD in a different module", decl);
	      inform (DECL_SOURCE_LOCATION (decl), "declared here");
	      return error_mark_node;
	    }

	  tree maybe_tmpl = decl;
	  if (CLASS_TYPE_P (t) && CLASSTYPE_IS_TEMPLATE (t))
	    maybe_tmpl = CLASSTYPE_TI_TEMPLATE (t);

	  if (DECL_LANG_SPECIFIC (decl)
	      && DECL_MODULE_IMPORT_P (decl)
	      && TREE_CODE (CP_DECL_CONTEXT (decl)) == NAMESPACE_DECL)
	    {
	      /* Push it into this TU's symbol slot.  */
	      gcc_checking_assert (current_namespace == CP_DECL_CONTEXT (decl));
	      if (maybe_tmpl != decl)
		/* We're in the template parm binding level.
		   Pushtag has logic to slide under that, but we're
		   not pushing a *new* type.  */
		push_nested_namespace (CP_DECL_CONTEXT (decl));

	      pushdecl (maybe_tmpl);
	      if (maybe_tmpl != decl)
		pop_nested_namespace (CP_DECL_CONTEXT (decl));
	    }

	  set_instantiating_module (maybe_tmpl);
	}
    }

  return t;
}

/* Create the binfo hierarchy for REF with (possibly NULL) base list
   BASE_LIST.  For each element on BASE_LIST the TREE_PURPOSE is an
   access_* node, and the TREE_VALUE is the type of the base-class.
   Non-NULL TREE_TYPE indicates virtual inheritance.  */

void
xref_basetypes (tree ref, tree base_list)
{
  tree *basep;
  tree binfo, base_binfo;
  unsigned max_vbases = 0; /* Maximum direct & indirect virtual bases.  */
  unsigned max_bases = 0;  /* Maximum direct bases.  */
  unsigned max_dvbases = 0; /* Maximum direct virtual bases.  */
  int i;
  tree default_access;
  tree igo_prev; /* Track Inheritance Graph Order.  */

  if (ref == error_mark_node)
    return;

  /* The base of a derived class is private by default, all others are
     public.  */
  default_access = (TREE_CODE (ref) == RECORD_TYPE
		    && CLASSTYPE_DECLARED_CLASS (ref)
		    ? access_private_node : access_public_node);

  /* First, make sure that any templates in base-classes are
     instantiated.  This ensures that if we call ourselves recursively
     we do not get confused about which classes are marked and which
     are not.  */
  basep = &base_list;
  while (*basep)
    {
      tree basetype = TREE_VALUE (*basep);

      /* The dependent_type_p call below should really be dependent_scope_p
	 so that we give a hard error about using an incomplete type as a
	 base, but we allow it with a pedwarn for backward
	 compatibility.  */
      if (processing_template_decl
	  && CLASS_TYPE_P (basetype) && TYPE_BEING_DEFINED (basetype))
	cxx_incomplete_type_diagnostic (NULL_TREE, basetype, DK_PEDWARN);
      if (!dependent_type_p (basetype)
	  && !complete_type_or_else (basetype, NULL))
	/* An incomplete type.  Remove it from the list.  */
	*basep = TREE_CHAIN (*basep);
      else
	{
	  max_bases++;
	  if (TREE_TYPE (*basep))
	    max_dvbases++;
	  if (CLASS_TYPE_P (basetype))
	    max_vbases += vec_safe_length (CLASSTYPE_VBASECLASSES (basetype));
	  basep = &TREE_CHAIN (*basep);
	}
    }
  max_vbases += max_dvbases;

  TYPE_MARKED_P (ref) = 1;

  /* The binfo slot should be empty, unless this is an (ill-formed)
     redefinition.  */
  gcc_assert (!TYPE_BINFO (ref) || TYPE_SIZE (ref));

  gcc_assert (TYPE_MAIN_VARIANT (ref) == ref);

  binfo = make_tree_binfo (max_bases);

  TYPE_BINFO (ref) = binfo;
  BINFO_OFFSET (binfo) = size_zero_node;
  BINFO_TYPE (binfo) = ref;

  /* Apply base-class info set up to the variants of this type.  */
  fixup_type_variants (ref);

  if (max_bases)
    {
      vec_alloc (BINFO_BASE_ACCESSES (binfo), max_bases);
      /* A C++98 POD cannot have base classes.  */
      CLASSTYPE_NON_LAYOUT_POD_P (ref) = true;

      if (TREE_CODE (ref) == UNION_TYPE)
	{
	  error ("derived union %qT invalid", ref);
	  return;
	}
    }

  if (max_bases > 1)
    warning (OPT_Wmultiple_inheritance,
	     "%qT defined with multiple direct bases", ref);

  if (max_vbases)
    {
      /* An aggregate can't have virtual base classes.  */
      CLASSTYPE_NON_AGGREGATE (ref) = true;

      vec_alloc (CLASSTYPE_VBASECLASSES (ref), max_vbases);

      if (max_dvbases)
	warning (OPT_Wvirtual_inheritance,
		 "%qT defined with direct virtual base", ref);
    }

  for (igo_prev = binfo; base_list; base_list = TREE_CHAIN (base_list))
    {
      tree access = TREE_PURPOSE (base_list);
      int via_virtual = TREE_TYPE (base_list) != NULL_TREE;
      tree basetype = TREE_VALUE (base_list);

      if (access == access_default_node)
	access = default_access;

      /* Before C++17, an aggregate cannot have base classes.  In C++17, an
	 aggregate can't have virtual, private, or protected base classes.  */
      if (cxx_dialect < cxx17
	  || access != access_public_node
	  || via_virtual)
	CLASSTYPE_NON_AGGREGATE (ref) = true;

      if (PACK_EXPANSION_P (basetype))
        basetype = PACK_EXPANSION_PATTERN (basetype);
      if (TREE_CODE (basetype) == TYPE_DECL)
	basetype = TREE_TYPE (basetype);
      if (!MAYBE_CLASS_TYPE_P (basetype) || TREE_CODE (basetype) == UNION_TYPE)
	{
	  error ("base type %qT fails to be a struct or class type",
		 basetype);
	  goto dropped_base;
	}

      base_binfo = NULL_TREE;
      if (CLASS_TYPE_P (basetype) && !dependent_scope_p (basetype))
	{
	  base_binfo = TYPE_BINFO (basetype);
	  /* The original basetype could have been a typedef'd type.  */
	  basetype = BINFO_TYPE (base_binfo);

	  /* Inherit flags from the base.  */
	  TYPE_HAS_NEW_OPERATOR (ref)
	    |= TYPE_HAS_NEW_OPERATOR (basetype);
	  TYPE_HAS_ARRAY_NEW_OPERATOR (ref)
	    |= TYPE_HAS_ARRAY_NEW_OPERATOR (basetype);
	  TYPE_GETS_DELETE (ref) |= TYPE_GETS_DELETE (basetype);
	  TYPE_HAS_CONVERSION (ref) |= TYPE_HAS_CONVERSION (basetype);
	  CLASSTYPE_DIAMOND_SHAPED_P (ref)
	    |= CLASSTYPE_DIAMOND_SHAPED_P (basetype);
	  CLASSTYPE_REPEATED_BASE_P (ref)
	    |= CLASSTYPE_REPEATED_BASE_P (basetype);
	}

      /* We must do this test after we've seen through a typedef
	 type.  */
      if (TYPE_MARKED_P (basetype))
	{
	  if (basetype == ref)
	    error ("recursive type %qT undefined", basetype);
	  else
	    error ("duplicate base type %qT invalid", basetype);
	  goto dropped_base;
	}

      if (PACK_EXPANSION_P (TREE_VALUE (base_list)))
        /* Regenerate the pack expansion for the bases. */
        basetype = make_pack_expansion (basetype);

      TYPE_MARKED_P (basetype) = 1;

      base_binfo = copy_binfo (base_binfo, basetype, ref,
			       &igo_prev, via_virtual);
      if (!BINFO_INHERITANCE_CHAIN (base_binfo))
	BINFO_INHERITANCE_CHAIN (base_binfo) = binfo;

      BINFO_BASE_APPEND (binfo, base_binfo);
      BINFO_BASE_ACCESS_APPEND (binfo, access);
      continue;

    dropped_base:
      /* Update max_vbases to reflect the reality that we are dropping
	 this base:  if it reaches zero we want to undo the vec_alloc
	 above to avoid inconsistencies during error-recovery: eg, in
	 build_special_member_call, CLASSTYPE_VBASECLASSES non null
	 and vtt null (c++/27952).  */
      if (via_virtual)
	max_vbases--;
      if (CLASS_TYPE_P (basetype))
	max_vbases
	  -= vec_safe_length (CLASSTYPE_VBASECLASSES (basetype));
    }

  if (CLASSTYPE_VBASECLASSES (ref)
      && max_vbases == 0)
    vec_free (CLASSTYPE_VBASECLASSES (ref));

  if (vec_safe_length (CLASSTYPE_VBASECLASSES (ref)) < max_vbases)
    /* If we didn't get max_vbases vbases, we must have shared at
       least one of them, and are therefore diamond shaped.  */
    CLASSTYPE_DIAMOND_SHAPED_P (ref) = 1;

  /* Unmark all the types.  */
  for (i = 0; BINFO_BASE_ITERATE (binfo, i, base_binfo); i++)
    TYPE_MARKED_P (BINFO_TYPE (base_binfo)) = 0;
  TYPE_MARKED_P (ref) = 0;

  /* Now see if we have a repeated base type.  */
  if (!CLASSTYPE_REPEATED_BASE_P (ref))
    {
      for (base_binfo = binfo; base_binfo;
	   base_binfo = TREE_CHAIN (base_binfo))
	{
	  if (TYPE_MARKED_P (BINFO_TYPE (base_binfo)))
	    {
	      CLASSTYPE_REPEATED_BASE_P (ref) = 1;
	      break;
	    }
	  TYPE_MARKED_P (BINFO_TYPE (base_binfo)) = 1;
	}
      for (base_binfo = binfo; base_binfo;
	   base_binfo = TREE_CHAIN (base_binfo))
	if (TYPE_MARKED_P (BINFO_TYPE (base_binfo)))
	  TYPE_MARKED_P (BINFO_TYPE (base_binfo)) = 0;
	else
	  break;
    }
}


/* Copies the enum-related properties from type SRC to type DST.
   Used with the underlying type of an enum and the enum itself.  */
static void
copy_type_enum (tree dst, tree src)
{
  tree t;
  for (t = dst; t; t = TYPE_NEXT_VARIANT (t))
    {
      TYPE_MIN_VALUE (t) = TYPE_MIN_VALUE (src);
      TYPE_MAX_VALUE (t) = TYPE_MAX_VALUE (src);
      TYPE_SIZE (t) = TYPE_SIZE (src);
      TYPE_SIZE_UNIT (t) = TYPE_SIZE_UNIT (src);
      SET_TYPE_MODE (dst, TYPE_MODE (src));
      TYPE_PRECISION (t) = TYPE_PRECISION (src);
      unsigned valign = TYPE_ALIGN (src);
      if (TYPE_USER_ALIGN (t))
	valign = MAX (valign, TYPE_ALIGN (t));
      else
	TYPE_USER_ALIGN (t) = TYPE_USER_ALIGN (src);
      SET_TYPE_ALIGN (t, valign);
      TYPE_UNSIGNED (t) = TYPE_UNSIGNED (src);
    }
}

/* Begin compiling the definition of an enumeration type.
   NAME is its name, 

   if ENUMTYPE is not NULL_TREE then the type has alredy been found.

   UNDERLYING_TYPE is the type that will be used as the storage for
   the enumeration type. This should be NULL_TREE if no storage type
   was specified.

   ATTRIBUTES are any attributes specified after the enum-key.

   SCOPED_ENUM_P is true if this is a scoped enumeration type.

   if IS_NEW is not NULL, gets TRUE iff a new type is created.

   Returns the type object, as yet incomplete.
   Also records info about it so that build_enumerator
   may be used to declare the individual values as they are read.  */

tree
start_enum (tree name, tree enumtype, tree underlying_type,
	    tree attributes, bool scoped_enum_p, bool *is_new)
{
  tree prevtype = NULL_TREE;
  gcc_assert (identifier_p (name));

  if (is_new)
    *is_new = false;
  /* [C++0x dcl.enum]p5:

    If not explicitly specified, the underlying type of a scoped
    enumeration type is int.  */
  if (!underlying_type && scoped_enum_p)
    underlying_type = integer_type_node;

  if (underlying_type)
    underlying_type = cv_unqualified (underlying_type);

  /* If this is the real definition for a previous forward reference,
     fill in the contents in the same object that used to be the
     forward reference.  */
  if (!enumtype)
    enumtype = lookup_and_check_tag (enum_type, name,
				     /*tag_scope=*/TAG_how::CURRENT_ONLY,
				     /*template_header_p=*/false);

  /* In case of a template_decl, the only check that should be deferred
     to instantiation time is the comparison of underlying types.  */
  if (enumtype && TREE_CODE (enumtype) == ENUMERAL_TYPE)
    {
      if (scoped_enum_p != SCOPED_ENUM_P (enumtype))
	{
	  error_at (input_location, "scoped/unscoped mismatch "
		    "in enum %q#T", enumtype);
	  inform (DECL_SOURCE_LOCATION (TYPE_MAIN_DECL (enumtype)),
		  "previous definition here");
	  enumtype = error_mark_node;
	}
      else if (ENUM_FIXED_UNDERLYING_TYPE_P (enumtype) != !! underlying_type)
	{
	  error_at (input_location, "underlying type mismatch "
		    "in enum %q#T", enumtype);
	  inform (DECL_SOURCE_LOCATION (TYPE_MAIN_DECL (enumtype)),
		  "previous definition here");
	  enumtype = error_mark_node;
	}
      else if (underlying_type && ENUM_UNDERLYING_TYPE (enumtype)
	       && !same_type_p (underlying_type,
				ENUM_UNDERLYING_TYPE (enumtype)))
	{
	  error_at (input_location, "different underlying type "
		    "in enum %q#T", enumtype);
	  inform (DECL_SOURCE_LOCATION (TYPE_MAIN_DECL (enumtype)),
		  "previous definition here");
	  underlying_type = NULL_TREE;
	}

      if (modules_p ())
	{
	  if (!module_may_redeclare (TYPE_NAME (enumtype)))
	    {
	      error ("cannot define %qD in different module",
		     TYPE_NAME (enumtype));
	      inform (DECL_SOURCE_LOCATION (TYPE_NAME (enumtype)),
		      "declared here");
	      enumtype = error_mark_node;
	    }
	  set_instantiating_module (TYPE_NAME (enumtype));
	}
    }

  if (!enumtype || TREE_CODE (enumtype) != ENUMERAL_TYPE
      || processing_template_decl)
    {
      /* In case of error, make a dummy enum to allow parsing to
	 continue.  */
      if (enumtype == error_mark_node)
	{
	  name = make_anon_name ();
	  enumtype = NULL_TREE;
	}

      /* enumtype may be an ENUMERAL_TYPE if this is a redefinition
         of an opaque enum, or an opaque enum of an already defined
	 enumeration (C++11).
	 In any other case, it'll be NULL_TREE. */
      if (!enumtype)
	{
	  if (is_new)
	    *is_new = true;
	}
      prevtype = enumtype;

      /* Do not push the decl more than once.  */
      if (!enumtype
	  || TREE_CODE (enumtype) != ENUMERAL_TYPE)
	{
	  enumtype = cxx_make_type (ENUMERAL_TYPE);
	  enumtype = pushtag (name, enumtype);

	  /* std::byte aliases anything.  */
	  if (enumtype != error_mark_node
	      && TYPE_CONTEXT (enumtype) == std_node
	      && !strcmp ("byte", TYPE_NAME_STRING (enumtype)))
	    TYPE_ALIAS_SET (enumtype) = 0;
	}
      else
	  enumtype = xref_tag (enum_type, name);

      if (enumtype == error_mark_node)
	return error_mark_node;

      /* The enum is considered opaque until the opening '{' of the
	 enumerator list.  */
      SET_OPAQUE_ENUM_P (enumtype, true);
      ENUM_FIXED_UNDERLYING_TYPE_P (enumtype) = !! underlying_type;
    }

  SET_SCOPED_ENUM_P (enumtype, scoped_enum_p);

  cplus_decl_attributes (&enumtype, attributes, (int)ATTR_FLAG_TYPE_IN_PLACE);

  if (underlying_type)
    {
      if (ENUM_UNDERLYING_TYPE (enumtype))
	/* We already checked that it matches, don't change it to a different
	   typedef variant.  */;
      else if (CP_INTEGRAL_TYPE_P (underlying_type))
        {
	  copy_type_enum (enumtype, underlying_type);
          ENUM_UNDERLYING_TYPE (enumtype) = underlying_type;
        }
      else if (dependent_type_p (underlying_type))
	ENUM_UNDERLYING_TYPE (enumtype) = underlying_type;
      else
        error ("underlying type %qT of %qT must be an integral type", 
               underlying_type, enumtype);
    }

  /* If into a template class, the returned enum is always the first
     declaration (opaque or not) seen. This way all the references to
     this type will be to the same declaration. The following ones are used
     only to check for definition errors.  */
  if (prevtype && processing_template_decl)
    return prevtype;
  else
    return enumtype;
}

/* After processing and defining all the values of an enumeration type,
   install their decls in the enumeration type.
   ENUMTYPE is the type object.  */

void
finish_enum_value_list (tree enumtype)
{
  tree values;
  tree underlying_type;
  tree decl;
  tree value;
  tree minnode, maxnode;
  tree t;

  bool fixed_underlying_type_p 
    = ENUM_UNDERLYING_TYPE (enumtype) != NULL_TREE;

  /* We built up the VALUES in reverse order.  */
  TYPE_VALUES (enumtype) = nreverse (TYPE_VALUES (enumtype));

  /* For an enum defined in a template, just set the type of the values;
     all further processing is postponed until the template is
     instantiated.  We need to set the type so that tsubst of a CONST_DECL
     works.  */
  if (processing_template_decl)
    {
      for (values = TYPE_VALUES (enumtype);
	   values;
	   values = TREE_CHAIN (values))
	TREE_TYPE (TREE_VALUE (values)) = enumtype;
      return;
    }

  /* Determine the minimum and maximum values of the enumerators.  */
  if (TYPE_VALUES (enumtype))
    {
      minnode = maxnode = NULL_TREE;

      for (values = TYPE_VALUES (enumtype);
	   values;
	   values = TREE_CHAIN (values))
	{
	  decl = TREE_VALUE (values);

	  /* [dcl.enum]: Following the closing brace of an enum-specifier,
	     each enumerator has the type of its enumeration.  Prior to the
	     closing brace, the type of each enumerator is the type of its
	     initializing value.  */
	  TREE_TYPE (decl) = enumtype;

	  /* Update the minimum and maximum values, if appropriate.  */
	  value = DECL_INITIAL (decl);
	  if (TREE_CODE (value) != INTEGER_CST)
	    value = integer_zero_node;
	  /* Figure out what the minimum and maximum values of the
	     enumerators are.  */
	  if (!minnode)
	    minnode = maxnode = value;
	  else if (tree_int_cst_lt (maxnode, value))
	    maxnode = value;
	  else if (tree_int_cst_lt (value, minnode))
	    minnode = value;
	}
    }
  else
    /* [dcl.enum]

       If the enumerator-list is empty, the underlying type is as if
       the enumeration had a single enumerator with value 0.  */
    minnode = maxnode = integer_zero_node;

  if (!fixed_underlying_type_p)
    {
      /* Compute the number of bits require to represent all values of the
	 enumeration.  We must do this before the type of MINNODE and
	 MAXNODE are transformed, since tree_int_cst_min_precision relies
	 on the TREE_TYPE of the value it is passed.  */
      signop sgn = tree_int_cst_sgn (minnode) >= 0 ? UNSIGNED : SIGNED;
      int lowprec = tree_int_cst_min_precision (minnode, sgn);
      int highprec = tree_int_cst_min_precision (maxnode, sgn);
      int precision = MAX (lowprec, highprec);
      unsigned int itk;
      bool use_short_enum;

      /* Determine the underlying type of the enumeration.

         [dcl.enum]

         The underlying type of an enumeration is an integral type that
         can represent all the enumerator values defined in the
         enumeration.  It is implementation-defined which integral type is
         used as the underlying type for an enumeration except that the
         underlying type shall not be larger than int unless the value of
         an enumerator cannot fit in an int or unsigned int.

         We use "int" or an "unsigned int" as the underlying type, even if
         a smaller integral type would work, unless the user has
         explicitly requested that we use the smallest possible type.  The
         user can request that for all enumerations with a command line
         flag, or for just one enumeration with an attribute.  */

      use_short_enum = flag_short_enums
        || lookup_attribute ("packed", TYPE_ATTRIBUTES (enumtype));

      /* If the precision of the type was specified with an attribute and it
	 was too small, give an error.  Otherwise, use it.  */
      if (TYPE_PRECISION (enumtype))
	{
	  if (precision > TYPE_PRECISION (enumtype))
	    error ("specified mode too small for enumerated values");
	  else
	    {
	      use_short_enum = true;
	      precision = TYPE_PRECISION (enumtype);
	    }
	}

      for (itk = (use_short_enum ? itk_char : itk_int);
           itk != itk_none;
           itk++)
        {
          underlying_type = integer_types[itk];
          if (underlying_type != NULL_TREE
	      && TYPE_PRECISION (underlying_type) >= precision
              && TYPE_SIGN (underlying_type) == sgn)
            break;
        }
      if (itk == itk_none)
        {
          /* DR 377

             IF no integral type can represent all the enumerator values, the
             enumeration is ill-formed.  */
          error ("no integral type can represent all of the enumerator values "
                 "for %qT", enumtype);
          precision = TYPE_PRECISION (long_long_integer_type_node);
          underlying_type = integer_types[itk_unsigned_long_long];
        }

      /* [dcl.enum]

         The value of sizeof() applied to an enumeration type, an object
         of an enumeration type, or an enumerator, is the value of sizeof()
         applied to the underlying type.  */
      copy_type_enum (enumtype, underlying_type);

      /* Compute the minimum and maximum values for the type.

	 [dcl.enum]

	 For an enumeration where emin is the smallest enumerator and emax
	 is the largest, the values of the enumeration are the values of the
	 underlying type in the range bmin to bmax, where bmin and bmax are,
	 respectively, the smallest and largest values of the smallest bit-
	 field that can store emin and emax.  */

      /* The middle-end currently assumes that types with TYPE_PRECISION
	 narrower than their underlying type are suitably zero or sign
	 extended to fill their mode.  Similarly, it assumes that the front
	 end assures that a value of a particular type must be within
	 TYPE_MIN_VALUE and TYPE_MAX_VALUE.

	 We used to set these fields based on bmin and bmax, but that led
	 to invalid assumptions like optimizing away bounds checking.  So
	 now we just set the TYPE_PRECISION, TYPE_MIN_VALUE, and
	 TYPE_MAX_VALUE to the values for the mode above and only restrict
	 the ENUM_UNDERLYING_TYPE for the benefit of diagnostics.  */
      ENUM_UNDERLYING_TYPE (enumtype)
	= build_distinct_type_copy (underlying_type);
      TYPE_PRECISION (ENUM_UNDERLYING_TYPE (enumtype)) = precision;
      set_min_and_max_values_for_integral_type
        (ENUM_UNDERLYING_TYPE (enumtype), precision, sgn);

      /* If -fstrict-enums, still constrain TYPE_MIN/MAX_VALUE.  */
      if (flag_strict_enums)
	set_min_and_max_values_for_integral_type (enumtype, precision, sgn);
    }
  else
    underlying_type = ENUM_UNDERLYING_TYPE (enumtype);

  /* If the enum is exported, mark the consts too.  */
  bool export_p = (UNSCOPED_ENUM_P (enumtype)
		   && DECL_MODULE_EXPORT_P (TYPE_STUB_DECL (enumtype))
		   && at_namespace_scope_p ());

  /* Convert each of the enumerators to the type of the underlying
     type of the enumeration.  */
  for (values = TYPE_VALUES (enumtype); values; values = TREE_CHAIN (values))
    {
      decl = TREE_VALUE (values);
      iloc_sentinel ils (DECL_SOURCE_LOCATION (decl));
      if (fixed_underlying_type_p)
        /* If the enumeration type has a fixed underlying type, we
           already checked all of the enumerator values.  */
        value = DECL_INITIAL (decl);
      else
        value = perform_implicit_conversion (underlying_type,
                                             DECL_INITIAL (decl),
                                             tf_warning_or_error);
      /* Do not clobber shared ints.  */
      if (value != error_mark_node)
	{
	  value = copy_node (value);

	  TREE_TYPE (value) = enumtype;
	}
      DECL_INITIAL (decl) = value;
      if (export_p)
	DECL_MODULE_EXPORT_P (decl) = true;
    }

  /* Fix up all variant types of this enum type.  */
  for (t = TYPE_MAIN_VARIANT (enumtype); t; t = TYPE_NEXT_VARIANT (t))
    TYPE_VALUES (t) = TYPE_VALUES (enumtype);

  if (at_class_scope_p ()
      && COMPLETE_TYPE_P (current_class_type)
      && UNSCOPED_ENUM_P (enumtype))
    {
      insert_late_enum_def_bindings (current_class_type, enumtype);
      /* TYPE_FIELDS needs fixup.  */
      fixup_type_variants (current_class_type);
    }

  /* Finish debugging output for this type.  */
  rest_of_type_compilation (enumtype, namespace_bindings_p ());

  /* Each enumerator now has the type of its enumeration.  Clear the cache
     so that this change in types doesn't confuse us later on.  */
  clear_cv_and_fold_caches ();
}

/* Finishes the enum type. This is called only the first time an
   enumeration is seen, be it opaque or odinary.
   ENUMTYPE is the type object.  */

void
finish_enum (tree enumtype)
{
  if (processing_template_decl)
    {
      if (at_function_scope_p ())
	add_stmt (build_min (TAG_DEFN, enumtype));
      return;
    }

  /* If this is a forward declaration, there should not be any variants,
     though we can get a variant in the middle of an enum-specifier with
     wacky code like 'enum E { e = sizeof(const E*) };'  */
  gcc_assert (enumtype == TYPE_MAIN_VARIANT (enumtype)
	      && (TYPE_VALUES (enumtype)
		  || !TYPE_NEXT_VARIANT (enumtype)));
}

/* Build and install a CONST_DECL for an enumeration constant of the
   enumeration type ENUMTYPE whose NAME and VALUE (if any) are provided.
   Apply ATTRIBUTES if available.  LOC is the location of NAME.
   Assignment of sequential values by default is handled here.  */

tree
build_enumerator (tree name, tree value, tree enumtype, tree attributes,
		  location_t loc)
{
  tree decl;
  tree context;
  tree type;

  /* scalar_constant_value will pull out this expression, so make sure
     it's folded as appropriate.  */
  if (processing_template_decl)
    value = fold_non_dependent_expr (value);

  /* If the VALUE was erroneous, pretend it wasn't there; that will
     result in the enum being assigned the next value in sequence.  */
  if (value == error_mark_node)
    value = NULL_TREE;

  /* Remove no-op casts from the value.  */
  if (value)
    STRIP_TYPE_NOPS (value);

  if (! processing_template_decl)
    {
      /* Validate and default VALUE.  */
      if (value != NULL_TREE)
	{
	  if (!ENUM_UNDERLYING_TYPE (enumtype))
	    {
	      tree tmp_value = build_expr_type_conversion (WANT_INT | WANT_ENUM,
							   value, true);
	      if (tmp_value)
		value = tmp_value;
	    }
	  else if (! INTEGRAL_OR_UNSCOPED_ENUMERATION_TYPE_P
		   (TREE_TYPE (value)))
	    value = perform_implicit_conversion_flags
	      (ENUM_UNDERLYING_TYPE (enumtype), value, tf_warning_or_error,
	       LOOKUP_IMPLICIT | LOOKUP_NO_NARROWING);

	  if (value == error_mark_node)
	    value = NULL_TREE;

	  if (value != NULL_TREE)
	    {
	      if (! INTEGRAL_OR_UNSCOPED_ENUMERATION_TYPE_P
		  (TREE_TYPE (value)))
		{
		  error_at (cp_expr_loc_or_input_loc (value),
			    "enumerator value for %qD must have integral or "
			    "unscoped enumeration type", name);
		  value = NULL_TREE;
		}
	      else
		{
		  value = cxx_constant_value (value);

		  if (TREE_CODE (value) != INTEGER_CST)
		    {
		      error ("enumerator value for %qD is not an integer "
			     "constant", name);
		      value = NULL_TREE;
		    }
		}
	    }
	}

      /* Default based on previous value.  */
      if (value == NULL_TREE)
	{
	  if (TYPE_VALUES (enumtype))
	    {
	      tree prev_value;

	      /* C++03 7.2/4: If no initializer is specified for the first
		 enumerator, the type is an unspecified integral
		 type. Otherwise the type is the same as the type of the
		 initializing value of the preceding enumerator unless the
		 incremented value is not representable in that type, in
		 which case the type is an unspecified integral type
		 sufficient to contain the incremented value.  */
	      prev_value = DECL_INITIAL (TREE_VALUE (TYPE_VALUES (enumtype)));
	      if (TREE_CODE (prev_value) != INTEGER_CST)
		value = error_mark_node;
	      else
		{
		  wi::overflow_type overflowed;
		  tree type = TREE_TYPE (prev_value);
		  signop sgn = TYPE_SIGN (type);
		  widest_int wi = wi::add (wi::to_widest (prev_value), 1, sgn,
					   &overflowed);
		  if (!overflowed)
		    {
		      bool pos = !wi::neg_p (wi, sgn);
		      if (!wi::fits_to_tree_p (wi, type))
			{
			  unsigned int itk;
			  for (itk = itk_int; itk != itk_none; itk++)
			    {
			      type = integer_types[itk];
			      if (type != NULL_TREE
				  && (pos || !TYPE_UNSIGNED (type))
				  && wi::fits_to_tree_p (wi, type))
				break;
			    }
			  if (type && cxx_dialect < cxx11
			      && itk > itk_unsigned_long)
			    pedwarn (input_location, OPT_Wlong_long,
				     pos ? G_("\
incremented enumerator value is too large for %<unsigned long%>") : G_("\
incremented enumerator value is too large for %<long%>"));
			}
		      if (type == NULL_TREE)
		        overflowed = wi::OVF_UNKNOWN;
		      else
			value = wide_int_to_tree (type, wi);
		    }

		  if (overflowed)
		    {
		      error ("overflow in enumeration values at %qD", name);
		      value = error_mark_node;
		    }
		}
	    }
	  else
	    value = integer_zero_node;
	}

      /* Remove no-op casts from the value.  */
      STRIP_TYPE_NOPS (value);

      /* If the underlying type of the enum is fixed, check whether
         the enumerator values fits in the underlying type.  If it
         does not fit, the program is ill-formed [C++0x dcl.enum].  */
      if (ENUM_UNDERLYING_TYPE (enumtype)
          && value
          && TREE_CODE (value) == INTEGER_CST)
        {
	  if (!int_fits_type_p (value, ENUM_UNDERLYING_TYPE (enumtype)))
	    error ("enumerator value %qE is outside the range of underlying "
		   "type %qT", value, ENUM_UNDERLYING_TYPE (enumtype));

          /* Convert the value to the appropriate type.  */
          value = fold_convert (ENUM_UNDERLYING_TYPE (enumtype), value);
        }
    }

  /* C++ associates enums with global, function, or class declarations.  */
  context = current_scope ();

  /* Build the actual enumeration constant.  Note that the enumeration
     constants have the underlying type of the enum (if it is fixed)
     or the type of their initializer (if the underlying type of the
     enum is not fixed):

      [ C++0x dcl.enum ]

        If the underlying type is fixed, the type of each enumerator
        prior to the closing brace is the underlying type; if the
        initializing value of an enumerator cannot be represented by
        the underlying type, the program is ill-formed. If the
        underlying type is not fixed, the type of each enumerator is
        the type of its initializing value.

    If the underlying type is not fixed, it will be computed by
    finish_enum and we will reset the type of this enumerator.  Of
    course, if we're processing a template, there may be no value.  */
  type = value ? TREE_TYPE (value) : NULL_TREE;

  decl = build_decl (loc, CONST_DECL, name, type);
  
  DECL_CONTEXT (decl) = enumtype;
  TREE_CONSTANT (decl) = 1;
  TREE_READONLY (decl) = 1;
  DECL_INITIAL (decl) = value;

  if (attributes)
    cplus_decl_attributes (&decl, attributes, 0);

  if (context && context == current_class_type && !SCOPED_ENUM_P (enumtype))
    {
      /* In something like `struct S { enum E { i = 7 }; };' we put `i'
	 on the TYPE_FIELDS list for `S'.  (That's so that you can say
	 things like `S::i' later.)  */

      /* The enumerator may be getting declared outside of its enclosing
	 class, like so:

	   class S { public: enum E : int; }; enum S::E : int { i = 7; };

	 For which case we need to make sure that the access of `S::i'
	 matches the access of `S::E'.  */
      auto cas = make_temp_override (current_access_specifier);
      set_current_access_from_decl (TYPE_NAME (enumtype));
      finish_member_declaration (decl);
    }
  else
    pushdecl (decl);

  /* Add this enumeration constant to the list for this type.  */
  TYPE_VALUES (enumtype) = tree_cons (name, decl, TYPE_VALUES (enumtype));

  return decl;
}

/* Look for an enumerator with the given NAME within the enumeration
   type ENUMTYPE.  This routine is used primarily for qualified name
   lookup into an enumerator in C++0x, e.g.,

     enum class Color { Red, Green, Blue };

     Color color = Color::Red;

   Returns the value corresponding to the enumerator, or
   NULL_TREE if no such enumerator was found.  */
tree
lookup_enumerator (tree enumtype, tree name)
{
  tree e;
  gcc_assert (enumtype && TREE_CODE (enumtype) == ENUMERAL_TYPE);

  e = purpose_member (name, TYPE_VALUES (enumtype));
  return e? TREE_VALUE (e) : NULL_TREE;
}

/* Implement LANG_HOOKS_SIMULATE_ENUM_DECL.  */

tree
cxx_simulate_enum_decl (location_t loc, const char *name,
			vec<string_int_pair> *values)
{
  location_t saved_loc = input_location;
  input_location = loc;

  tree enumtype = start_enum (get_identifier (name), NULL_TREE, NULL_TREE,
			      NULL_TREE, false, NULL);
  if (!OPAQUE_ENUM_P (enumtype))
    {
      error_at (loc, "multiple definition of %q#T", enumtype);
      inform (DECL_SOURCE_LOCATION (TYPE_MAIN_DECL (enumtype)),
	      "previous definition here");
      return enumtype;
    }
  SET_OPAQUE_ENUM_P (enumtype, false);
  DECL_SOURCE_LOCATION (TYPE_NAME (enumtype)) = loc;

  for (const string_int_pair &value : values)
    build_enumerator (get_identifier (value.first),
		      build_int_cst (integer_type_node, value.second),
		      enumtype, NULL_TREE, loc);

  finish_enum_value_list (enumtype);
  finish_enum (enumtype);

  input_location = saved_loc;
  return enumtype;
}

/* Implement LANG_HOOKS_SIMULATE_RECORD_DECL.  */

tree
cxx_simulate_record_decl (location_t loc, const char *name,
			  array_slice<const tree> fields)
{
  iloc_sentinel ils (loc);

  tree ident = get_identifier (name);
  tree type = xref_tag (/*tag_code=*/record_type, ident);
  if (type != error_mark_node
      && (TREE_CODE (type) != RECORD_TYPE || COMPLETE_TYPE_P (type)))
    {
      error ("redefinition of %q#T", type);
      type = error_mark_node;
    }
  if (type == error_mark_node)
    return lhd_simulate_record_decl (loc, name, fields);

  xref_basetypes (type, NULL_TREE);
  type = begin_class_definition (type);
  if (type == error_mark_node)
    return lhd_simulate_record_decl (loc, name, fields);

  for (tree field : fields)
    finish_member_declaration (field);

  type = finish_struct (type, NULL_TREE);

  tree decl = build_decl (loc, TYPE_DECL, ident, type);
  set_underlying_type (decl);
  lang_hooks.decls.pushdecl (decl);

  return type;
}

/* We're defining DECL.  Make sure that its type is OK.  */

static void
check_function_type (tree decl, tree current_function_parms)
{
  tree fntype = TREE_TYPE (decl);
  tree return_type = complete_type (TREE_TYPE (fntype));

  /* In a function definition, arg types must be complete.  */
  require_complete_types_for_parms (current_function_parms);

  if (dependent_type_p (return_type)
      || type_uses_auto (return_type))
    return;
  if (!COMPLETE_OR_VOID_TYPE_P (return_type))
    {
      tree args = TYPE_ARG_TYPES (fntype);

      error ("return type %q#T is incomplete", return_type);

      /* Make it return void instead.  */
      if (TREE_CODE (fntype) == METHOD_TYPE)
	fntype = build_method_type_directly (TREE_TYPE (TREE_VALUE (args)),
					     void_type_node,
					     TREE_CHAIN (args));
      else
	fntype = build_function_type (void_type_node, args);
      fntype = (cp_build_type_attribute_variant
		(fntype, TYPE_ATTRIBUTES (TREE_TYPE (decl))));
      fntype = cxx_copy_lang_qualifiers (fntype, TREE_TYPE (decl));
      TREE_TYPE (decl) = fntype;
    }
  else
    {
      abstract_virtuals_error (decl, TREE_TYPE (fntype));
      maybe_warn_parm_abi (TREE_TYPE (fntype),
			   DECL_SOURCE_LOCATION (decl));
    }
}

/* True iff FN is an implicitly-defined default constructor.  */

static bool
implicit_default_ctor_p (tree fn)
{
  return (DECL_CONSTRUCTOR_P (fn)
	  && !user_provided_p (fn)
	  && sufficient_parms_p (FUNCTION_FIRST_USER_PARMTYPE (fn)));
}

/* Clobber the contents of *this to let the back end know that the object
   storage is dead when we enter the constructor or leave the destructor.  */

static tree
build_clobber_this ()
{
  /* Clobbering an empty base is pointless, and harmful if its one byte
     TYPE_SIZE overlays real data.  */
  if (is_empty_class (current_class_type))
    return void_node;

  /* If we have virtual bases, clobber the whole object, but only if we're in
     charge.  If we don't have virtual bases, clobber the as-base type so we
     don't mess with tail padding.  */
  bool vbases = CLASSTYPE_VBASECLASSES (current_class_type);

  tree ctype = current_class_type;
  if (!vbases)
    ctype = CLASSTYPE_AS_BASE (ctype);

  tree clobber = build_clobber (ctype);

  tree thisref = current_class_ref;
  if (ctype != current_class_type)
    {
      thisref = build_nop (build_reference_type (ctype), current_class_ptr);
      thisref = convert_from_reference (thisref);
    }

  tree exprstmt = build2 (MODIFY_EXPR, void_type_node, thisref, clobber);
  if (vbases)
    exprstmt = build_if_in_charge (exprstmt);

  return exprstmt;
}

/* Create the FUNCTION_DECL for a function definition.
   DECLSPECS and DECLARATOR are the parts of the declaration;
   they describe the function's name and the type it returns,
   but twisted together in a fashion that parallels the syntax of C.

   FLAGS is a bitwise or of SF_PRE_PARSED (indicating that the
   DECLARATOR is really the DECL for the function we are about to
   process and that DECLSPECS should be ignored), SF_INCLASS_INLINE
   indicating that the function is an inline defined in-class.

   This function creates a binding context for the function body
   as well as setting up the FUNCTION_DECL in current_function_decl.

   For C++, we must first check whether that datum makes any sense.
   For example, "class A local_a(1,2);" means that variable local_a
   is an aggregate of type A, which should have a constructor
   applied to it with the argument list [1, 2].

   On entry, DECL_INITIAL (decl1) should be NULL_TREE or error_mark_node,
   or may be a BLOCK if the function has been defined previously
   in this translation unit.  On exit, DECL_INITIAL (decl1) will be
   error_mark_node if the function has never been defined, or
   a BLOCK if the function has been defined somewhere.  */

bool
start_preparsed_function (tree decl1, tree attrs, int flags)
{
  tree ctype = NULL_TREE;
  bool doing_friend = false;

  /* Sanity check.  */
  gcc_assert (VOID_TYPE_P (TREE_VALUE (void_list_node)));
  gcc_assert (TREE_CHAIN (void_list_node) == NULL_TREE);

  tree fntype = TREE_TYPE (decl1);
  if (TREE_CODE (fntype) == METHOD_TYPE)
    ctype = TYPE_METHOD_BASETYPE (fntype);
  else
    {
      ctype = DECL_FRIEND_CONTEXT (decl1);

      if (ctype)
	doing_friend = true;
    }

  if (DECL_DECLARED_INLINE_P (decl1)
      && lookup_attribute ("noinline", attrs))
    warning_at (DECL_SOURCE_LOCATION (decl1), 0,
		"inline function %qD given attribute %qs", decl1, "noinline");

  /* Handle gnu_inline attribute.  */
  if (GNU_INLINE_P (decl1))
    {
      DECL_EXTERNAL (decl1) = 1;
      DECL_NOT_REALLY_EXTERN (decl1) = 0;
      DECL_INTERFACE_KNOWN (decl1) = 1;
      DECL_DISREGARD_INLINE_LIMITS (decl1) = 1;
    }

  if (DECL_MAYBE_IN_CHARGE_CONSTRUCTOR_P (decl1))
    /* This is a constructor, we must ensure that any default args
       introduced by this definition are propagated to the clones
       now. The clones are used directly in overload resolution.  */
    adjust_clone_args (decl1);

  /* Sometimes we don't notice that a function is a static member, and
     build a METHOD_TYPE for it.  Fix that up now.  */
  gcc_assert (!(ctype != NULL_TREE && DECL_STATIC_FUNCTION_P (decl1)
		&& TREE_CODE (TREE_TYPE (decl1)) == METHOD_TYPE));

  /* Set up current_class_type, and enter the scope of the class, if
     appropriate.  */
  if (ctype)
    push_nested_class (ctype);
  else if (DECL_STATIC_FUNCTION_P (decl1))
    push_nested_class (DECL_CONTEXT (decl1));

  /* Now that we have entered the scope of the class, we must restore
     the bindings for any template parameters surrounding DECL1, if it
     is an inline member template.  (Order is important; consider the
     case where a template parameter has the same name as a field of
     the class.)  It is not until after this point that
     PROCESSING_TEMPLATE_DECL is guaranteed to be set up correctly.  */
  if (flags & SF_INCLASS_INLINE)
    maybe_begin_member_template_processing (decl1);

  /* Effective C++ rule 15.  */
  if (warn_ecpp
      && DECL_ASSIGNMENT_OPERATOR_P (decl1)
      && DECL_OVERLOADED_OPERATOR_IS (decl1, NOP_EXPR)
      && VOID_TYPE_P (TREE_TYPE (fntype)))
    warning (OPT_Weffc__,
	     "%<operator=%> should return a reference to %<*this%>");

  /* Make the init_value nonzero so pushdecl knows this is not tentative.
     error_mark_node is replaced below (in poplevel) with the BLOCK.  */
  if (!DECL_INITIAL (decl1))
    DECL_INITIAL (decl1) = error_mark_node;

  /* This function exists in static storage.
     (This does not mean `static' in the C sense!)  */
  TREE_STATIC (decl1) = 1;

  /* We must call push_template_decl after current_class_type is set
     up.  (If we are processing inline definitions after exiting a
     class scope, current_class_type will be NULL_TREE until set above
     by push_nested_class.)  */
  if (processing_template_decl)
    {
      tree newdecl1 = push_template_decl (decl1, doing_friend);
      if (newdecl1 == error_mark_node)
	{
	  if (ctype || DECL_STATIC_FUNCTION_P (decl1))
	    pop_nested_class ();
	  return false;
	}
      decl1 = newdecl1;
    }

  /* Make sure the parameter and return types are reasonable.  When
     you declare a function, these types can be incomplete, but they
     must be complete when you define the function.  */
  check_function_type (decl1, DECL_ARGUMENTS (decl1));

  /* Build the return declaration for the function.  */
  tree restype = TREE_TYPE (fntype);

  if (DECL_RESULT (decl1) == NULL_TREE)
    {
      tree resdecl;

      resdecl = build_decl (input_location, RESULT_DECL, 0, restype);
      DECL_ARTIFICIAL (resdecl) = 1;
      DECL_IGNORED_P (resdecl) = 1;
      DECL_RESULT (decl1) = resdecl;

      cp_apply_type_quals_to_decl (cp_type_quals (restype), resdecl);
    }

  /* Record the decl so that the function name is defined.
     If we already have a decl for this name, and it is a FUNCTION_DECL,
     use the old decl.  */
  if (!processing_template_decl && !(flags & SF_PRE_PARSED))
    {
      /* A specialization is not used to guide overload resolution.  */
      if (!DECL_FUNCTION_MEMBER_P (decl1)
	  && !(DECL_USE_TEMPLATE (decl1) &&
	       PRIMARY_TEMPLATE_P (DECL_TI_TEMPLATE (decl1))))
	{
	  tree olddecl = pushdecl (decl1);

	  if (olddecl == error_mark_node)
	    /* If something went wrong when registering the declaration,
	       use DECL1; we have to have a FUNCTION_DECL to use when
	       parsing the body of the function.  */
	    ;
	  else
	    {
	      /* Otherwise, OLDDECL is either a previous declaration
		 of the same function or DECL1 itself.  */

	      if (warn_missing_declarations
		  && olddecl == decl1
		  && !DECL_MAIN_P (decl1)
		  && TREE_PUBLIC (decl1)
		  && !DECL_DECLARED_INLINE_P (decl1))
		{
		  tree context;

		  /* Check whether DECL1 is in an anonymous
		     namespace.  */
		  for (context = DECL_CONTEXT (decl1);
		       context;
		       context = DECL_CONTEXT (context))
		    {
		      if (TREE_CODE (context) == NAMESPACE_DECL
			  && DECL_NAME (context) == NULL_TREE)
			break;
		    }

		  if (context == NULL)
		    warning_at (DECL_SOURCE_LOCATION (decl1),
				OPT_Wmissing_declarations,
				"no previous declaration for %qD", decl1);
		}

	      decl1 = olddecl;
	    }
	}
      else
	{
	  /* We need to set the DECL_CONTEXT.  */
	  if (!DECL_CONTEXT (decl1) && DECL_TEMPLATE_INFO (decl1))
	    DECL_CONTEXT (decl1) = DECL_CONTEXT (DECL_TI_TEMPLATE (decl1));
	}
      fntype = TREE_TYPE (decl1);
      restype = TREE_TYPE (fntype);

      /* If #pragma weak applies, mark the decl appropriately now.
	 The pragma only applies to global functions.  Because
	 determining whether or not the #pragma applies involves
	 computing the mangled name for the declaration, we cannot
	 apply the pragma until after we have merged this declaration
	 with any previous declarations; if the original declaration
	 has a linkage specification, that specification applies to
	 the definition as well, and may affect the mangled name.  */
      if (DECL_FILE_SCOPE_P (decl1))
	maybe_apply_pragma_weak (decl1);
    }

  /* We are now in the scope of the function being defined.  */
  current_function_decl = decl1;

  /* Save the parm names or decls from this function's declarator
     where store_parm_decls will find them.  */
  tree current_function_parms = DECL_ARGUMENTS (decl1);

  /* Let the user know we're compiling this function.  */
  announce_function (decl1);

  gcc_assert (DECL_INITIAL (decl1));

  /* This function may already have been parsed, in which case just
     return; our caller will skip over the body without parsing.  */
  if (DECL_INITIAL (decl1) != error_mark_node)
    return true;

  /* Initialize RTL machinery.  We cannot do this until
     CURRENT_FUNCTION_DECL and DECL_RESULT are set up.  We do this
     even when processing a template; this is how we get
     CFUN set up, and our per-function variables initialized.
     FIXME factor out the non-RTL stuff.  */
  cp_binding_level *bl = current_binding_level;
  allocate_struct_function (decl1, processing_template_decl);

  /* Initialize the language data structures.  Whenever we start
     a new function, we destroy temporaries in the usual way.  */
  cfun->language = ggc_cleared_alloc<language_function> ();
  current_stmt_tree ()->stmts_are_full_exprs_p = 1;
  current_binding_level = bl;

  /* If we are (erroneously) defining a function that we have already
     defined before, wipe out what we knew before.  */
  gcc_checking_assert (!DECL_PENDING_INLINE_P (decl1));
  FNDECL_USED_AUTO (decl1) = false;
  DECL_SAVED_AUTO_RETURN_TYPE (decl1) = NULL;

  if (!processing_template_decl && type_uses_auto (restype))
    {
      FNDECL_USED_AUTO (decl1) = true;
      DECL_SAVED_AUTO_RETURN_TYPE (decl1) = restype;
    }

  /* Start the statement-tree, start the tree now.  */
  DECL_SAVED_TREE (decl1) = push_stmt_list ();

  if (ctype && !doing_friend && !DECL_STATIC_FUNCTION_P (decl1))
    {
      /* We know that this was set up by `grokclassfn'.  We do not
	 wait until `store_parm_decls', since evil parse errors may
	 never get us to that point.  Here we keep the consistency
	 between `current_class_type' and `current_class_ptr'.  */
      tree t = DECL_ARGUMENTS (decl1);

      gcc_assert (t != NULL_TREE && TREE_CODE (t) == PARM_DECL);
      gcc_assert (TYPE_PTR_P (TREE_TYPE (t)));

      cp_function_chain->x_current_class_ref
	= cp_build_fold_indirect_ref (t);
      /* Set this second to avoid shortcut in cp_build_indirect_ref.  */
      cp_function_chain->x_current_class_ptr = t;

      /* Constructors and destructors need to know whether they're "in
	 charge" of initializing virtual base classes.  */
      t = DECL_CHAIN (t);
      if (DECL_HAS_IN_CHARGE_PARM_P (decl1))
	{
	  current_in_charge_parm = t;
	  t = DECL_CHAIN (t);
	}
      if (DECL_HAS_VTT_PARM_P (decl1))
	{
	  gcc_assert (DECL_NAME (t) == vtt_parm_identifier);
	  current_vtt_parm = t;
	}
    }

  bool honor_interface = (!DECL_TEMPLATE_INSTANTIATION (decl1)
			  /* Implicitly-defined methods (like the
			     destructor for a class in which no destructor
			     is explicitly declared) must not be defined
			     until their definition is needed.  So, we
			     ignore interface specifications for
			     compiler-generated functions.  */
			  && !DECL_ARTIFICIAL (decl1));
  struct c_fileinfo *finfo
    = get_fileinfo (LOCATION_FILE (DECL_SOURCE_LOCATION (decl1)));

  if (processing_template_decl)
    /* Don't mess with interface flags.  */;
  else if (DECL_INTERFACE_KNOWN (decl1))
    {
      tree ctx = decl_function_context (decl1);

      if (DECL_NOT_REALLY_EXTERN (decl1))
	DECL_EXTERNAL (decl1) = 0;

      if (ctx != NULL_TREE && vague_linkage_p (ctx))
	/* This is a function in a local class in an extern inline
	   or template function.  */
	comdat_linkage (decl1);
    }
  /* If this function belongs to an interface, it is public.
     If it belongs to someone else's interface, it is also external.
     This only affects inlines and template instantiations.  */
  else if (!finfo->interface_unknown && honor_interface)
    {
      if (DECL_DECLARED_INLINE_P (decl1)
	  || DECL_TEMPLATE_INSTANTIATION (decl1))
	{
	  DECL_EXTERNAL (decl1)
	    = (finfo->interface_only
	       || (DECL_DECLARED_INLINE_P (decl1)
		   && ! flag_implement_inlines
		   && !DECL_VINDEX (decl1)));

	  /* For WIN32 we also want to put these in linkonce sections.  */
	  maybe_make_one_only (decl1);
	}
      else
	DECL_EXTERNAL (decl1) = 0;
      DECL_INTERFACE_KNOWN (decl1) = 1;
      /* If this function is in an interface implemented in this file,
	 make sure that the back end knows to emit this function
	 here.  */
      if (!DECL_EXTERNAL (decl1))
	mark_needed (decl1);
    }
  else if (finfo->interface_unknown && finfo->interface_only
	   && honor_interface)
    {
      /* If MULTIPLE_SYMBOL_SPACES is defined and we saw a #pragma
	 interface, we will have both finfo->interface_unknown and
	 finfo->interface_only set.  In that case, we don't want to
	 use the normal heuristics because someone will supply a
	 #pragma implementation elsewhere, and deducing it here would
	 produce a conflict.  */
      comdat_linkage (decl1);
      DECL_EXTERNAL (decl1) = 0;
      DECL_INTERFACE_KNOWN (decl1) = 1;
      DECL_DEFER_OUTPUT (decl1) = 1;
    }
  else
    {
      /* This is a definition, not a reference.
	 So clear DECL_EXTERNAL, unless this is a GNU extern inline.  */
      if (!GNU_INLINE_P (decl1))
	DECL_EXTERNAL (decl1) = 0;

      if ((DECL_DECLARED_INLINE_P (decl1)
	   || DECL_TEMPLATE_INSTANTIATION (decl1))
	  && ! DECL_INTERFACE_KNOWN (decl1))
	DECL_DEFER_OUTPUT (decl1) = 1;
      else
	DECL_INTERFACE_KNOWN (decl1) = 1;
    }

  /* Determine the ELF visibility attribute for the function.  We must not
     do this before calling "pushdecl", as we must allow "duplicate_decls"
     to merge any attributes appropriately.  We also need to wait until
     linkage is set.  */
  if (!DECL_CLONED_FUNCTION_P (decl1))
    determine_visibility (decl1);

  if (!processing_template_decl)
    maybe_instantiate_noexcept (decl1);

  begin_scope (sk_function_parms, decl1);

  ++function_depth;

  if (DECL_DESTRUCTOR_P (decl1)
      || (DECL_CONSTRUCTOR_P (decl1)
	  && targetm.cxx.cdtor_returns_this ()))
    {
      cdtor_label = create_artificial_label (input_location);
      LABEL_DECL_CDTOR (cdtor_label) = true;
    }

  start_fname_decls ();

  store_parm_decls (current_function_parms);

  if (!processing_template_decl
      && (flag_lifetime_dse > 1)
      && DECL_CONSTRUCTOR_P (decl1)
      && !DECL_CLONED_FUNCTION_P (decl1)
      /* Clobbering an empty base is harmful if it overlays real data.  */
      && !is_empty_class (current_class_type)
      /* We can't clobber safely for an implicitly-defined default constructor
	 because part of the initialization might happen before we enter the
	 constructor, via AGGR_INIT_ZERO_FIRST (c++/68006).  */
      && !implicit_default_ctor_p (decl1))
    finish_expr_stmt (build_clobber_this ());

  if (!processing_template_decl
      && DECL_CONSTRUCTOR_P (decl1)
      && sanitize_flags_p (SANITIZE_VPTR)
      && !DECL_CLONED_FUNCTION_P (decl1)
      && !implicit_default_ctor_p (decl1))
    cp_ubsan_maybe_initialize_vtbl_ptrs (current_class_ptr);

  if (!DECL_OMP_DECLARE_REDUCTION_P (decl1))
    start_lambda_scope (decl1);

  return true;
}


/* Like start_preparsed_function, except that instead of a
   FUNCTION_DECL, this function takes DECLSPECS and DECLARATOR.

   Returns true on success.  If the DECLARATOR is not suitable
   for a function, we return false, which tells the parser to
   skip the entire function.  */

bool
start_function (cp_decl_specifier_seq *declspecs,
		const cp_declarator *declarator,
		tree attrs)
{
  tree decl1;

  decl1 = grokdeclarator (declarator, declspecs, FUNCDEF, 1, &attrs);
  invoke_plugin_callbacks (PLUGIN_START_PARSE_FUNCTION, decl1);
  if (decl1 == error_mark_node)
    return false;

  if (DECL_MAIN_P (decl1))
    /* main must return int.  grokfndecl should have corrected it
       (and issued a diagnostic) if the user got it wrong.  */
    gcc_assert (same_type_p (TREE_TYPE (TREE_TYPE (decl1)),
			     integer_type_node));

  return start_preparsed_function (decl1, attrs, /*flags=*/SF_DEFAULT);
}

/* Returns true iff an EH_SPEC_BLOCK should be created in the body of
   FN.  */

static bool
use_eh_spec_block (tree fn)
{
  return (flag_exceptions && flag_enforce_eh_specs
	  && !processing_template_decl
	  /* We insert the EH_SPEC_BLOCK only in the original
	     function; then, it is copied automatically to the
	     clones.  */
	  && !DECL_CLONED_FUNCTION_P (fn)
	  /* Implicitly-generated constructors and destructors have
	     exception specifications.  However, those specifications
	     are the union of the possible exceptions specified by the
	     constructors/destructors for bases and members, so no
	     unallowed exception will ever reach this function.  By
	     not creating the EH_SPEC_BLOCK we save a little memory,
	     and we avoid spurious warnings about unreachable
	     code.  */
	  && !DECL_DEFAULTED_FN (fn)
	  && !type_throw_all_p (TREE_TYPE (fn)));
}

/* Helper function to push ARGS into the current lexical scope.  DECL
   is the function declaration.  NONPARMS is used to handle enum
   constants.  */

void
do_push_parm_decls (tree decl, tree args, tree *nonparms)
{
  /* If we're doing semantic analysis, then we'll call pushdecl
     for each of these.  We must do them in reverse order so that
     they end in the correct forward order.  */
  args = nreverse (args);

  tree next;
  for (tree parm = args; parm; parm = next)
    {
      next = DECL_CHAIN (parm);
      if (TREE_CODE (parm) == PARM_DECL)
	pushdecl (parm);
      else if (nonparms)
	{
	  /* If we find an enum constant or a type tag, put it aside for
	     the moment.  */
	  TREE_CHAIN (parm) = NULL_TREE;
	  *nonparms = chainon (*nonparms, parm);
	}
    }

  /* Get the decls in their original chain order and record in the
     function.  This is all and only the PARM_DECLs that were
     pushed into scope by the loop above.  */
  DECL_ARGUMENTS (decl) = get_local_decls ();
}

/* Store the parameter declarations into the current function declaration.
   This is called after parsing the parameter declarations, before
   digesting the body of the function.

   Also install to binding contour return value identifier, if any.  */

static void
store_parm_decls (tree current_function_parms)
{
  tree fndecl = current_function_decl;

  /* This is a chain of any other decls that came in among the parm
     declarations.  If a parm is declared with  enum {foo, bar} x;
     then CONST_DECLs for foo and bar are put here.  */
  tree nonparms = NULL_TREE;

  if (current_function_parms)
    {
      /* This case is when the function was defined with an ANSI prototype.
	 The parms already have decls, so we need not do anything here
	 except record them as in effect
	 and complain if any redundant old-style parm decls were written.  */

      tree specparms = current_function_parms;

      /* Must clear this because it might contain TYPE_DECLs declared
	     at class level.  */
      current_binding_level->names = NULL;

      do_push_parm_decls (fndecl, specparms, &nonparms);
    }
  else
    DECL_ARGUMENTS (fndecl) = NULL_TREE;

  /* Now store the final chain of decls for the arguments
     as the decl-chain of the current lexical scope.
     Put the enumerators in as well, at the front so that
     DECL_ARGUMENTS is not modified.  */
  current_binding_level->names = chainon (nonparms, DECL_ARGUMENTS (fndecl));

  if (use_eh_spec_block (current_function_decl))
    current_eh_spec_block = begin_eh_spec_block ();
}


/* Set the return value of the constructor (if present).  */

static void
finish_constructor_body (void)
{
  tree val;
  tree exprstmt;

  if (targetm.cxx.cdtor_returns_this ())
    {
      /* Any return from a constructor will end up here.  */
      add_stmt (build_stmt (input_location, LABEL_EXPR, cdtor_label));

      val = DECL_ARGUMENTS (current_function_decl);
      suppress_warning (val, OPT_Wuse_after_free);
      val = build2 (MODIFY_EXPR, TREE_TYPE (val),
		    DECL_RESULT (current_function_decl), val);
      /* Return the address of the object.  */
      exprstmt = build_stmt (input_location, RETURN_EXPR, val);
      add_stmt (exprstmt);
    }
}

/* Do all the processing for the beginning of a destructor; set up the
   vtable pointers and cleanups for bases and members.  */

static void
begin_destructor_body (void)
{
  tree compound_stmt;

  /* If the CURRENT_CLASS_TYPE is incomplete, we will have already
     issued an error message.  We still want to try to process the
     body of the function, but initialize_vtbl_ptrs will crash if
     TYPE_BINFO is NULL.  */
  if (COMPLETE_TYPE_P (current_class_type))
    {
      compound_stmt = begin_compound_stmt (0);
      /* Make all virtual function table pointers in non-virtual base
	 classes point to CURRENT_CLASS_TYPE's virtual function
	 tables.  */
      initialize_vtbl_ptrs (current_class_ptr);
      finish_compound_stmt (compound_stmt);

      if (flag_lifetime_dse
	  /* Clobbering an empty base is harmful if it overlays real data.  */
	  && !is_empty_class (current_class_type))
      {
	if (sanitize_flags_p (SANITIZE_VPTR)
	    && (flag_sanitize_recover & SANITIZE_VPTR) == 0
	    && TYPE_CONTAINS_VPTR_P (current_class_type))
	  {
	    tree binfo = TYPE_BINFO (current_class_type);
	    tree ref
	      = cp_build_fold_indirect_ref (current_class_ptr);

	    tree vtbl_ptr = build_vfield_ref (ref, TREE_TYPE (binfo));
	    tree vtbl = build_zero_cst (TREE_TYPE (vtbl_ptr));
	    tree stmt = cp_build_modify_expr (input_location, vtbl_ptr,
					      NOP_EXPR, vtbl,
					      tf_warning_or_error);
	    /* If the vptr is shared with some virtual nearly empty base,
	       don't clear it if not in charge, the dtor of the virtual
	       nearly empty base will do that later.  */
	    if (CLASSTYPE_VBASECLASSES (current_class_type))
	      {
		tree c = current_class_type;
		while (CLASSTYPE_PRIMARY_BINFO (c))
		  {
		    if (BINFO_VIRTUAL_P (CLASSTYPE_PRIMARY_BINFO (c)))
		      {
			stmt = convert_to_void (stmt, ICV_STATEMENT,
						tf_warning_or_error);
			stmt = build_if_in_charge (stmt);
			break;
		      }
		    c = BINFO_TYPE (CLASSTYPE_PRIMARY_BINFO (c));
		  }
	      }
	    finish_decl_cleanup (NULL_TREE, stmt);
	  }
	else
	  finish_decl_cleanup (NULL_TREE, build_clobber_this ());
      }

      /* And insert cleanups for our bases and members so that they
	 will be properly destroyed if we throw.  */
      push_base_cleanups ();
    }
}

/* At the end of every destructor we generate code to delete the object if
   necessary.  Do that now.  */

static void
finish_destructor_body (void)
{
  tree exprstmt;

  /* Any return from a destructor will end up here; that way all base
     and member cleanups will be run when the function returns.  */
  add_stmt (build_stmt (input_location, LABEL_EXPR, cdtor_label));

  if (targetm.cxx.cdtor_returns_this ())
    {
      tree val;

      val = DECL_ARGUMENTS (current_function_decl);
      suppress_warning (val, OPT_Wuse_after_free);
      val = build2 (MODIFY_EXPR, TREE_TYPE (val),
		    DECL_RESULT (current_function_decl), val);
      /* Return the address of the object.  */
      exprstmt = build_stmt (input_location, RETURN_EXPR, val);
      add_stmt (exprstmt);
    }
}

/* Do the necessary processing for the beginning of a function body, which
   in this case includes member-initializers, but not the catch clauses of
   a function-try-block.  Currently, this means opening a binding level
   for the member-initializers (in a ctor), member cleanups (in a dtor),
   and capture proxies (in a lambda operator()).  */

tree
begin_function_body (void)
{
  if (! FUNCTION_NEEDS_BODY_BLOCK (current_function_decl))
    return NULL_TREE;

  if (processing_template_decl)
    /* Do nothing now.  */;
  else
    /* Always keep the BLOCK node associated with the outermost pair of
       curly braces of a function.  These are needed for correct
       operation of dwarfout.c.  */
    keep_next_level (true);

  tree stmt = begin_compound_stmt (BCS_FN_BODY);

  if (processing_template_decl)
    /* Do nothing now.  */;
  else if (DECL_DESTRUCTOR_P (current_function_decl))
    begin_destructor_body ();

  return stmt;
}

/* Do the processing for the end of a function body.  Currently, this means
   closing out the cleanups for fully-constructed bases and members, and in
   the case of the destructor, deleting the object if desired.  Again, this
   is only meaningful for [cd]tors, since they are the only functions where
   there is a significant distinction between the main body and any
   function catch clauses.  Handling, say, main() return semantics here
   would be wrong, as flowing off the end of a function catch clause for
   main() would also need to return 0.  */

void
finish_function_body (tree compstmt)
{
  if (compstmt == NULL_TREE)
    return;

  /* Close the block.  */
  finish_compound_stmt (compstmt);

  if (processing_template_decl)
    /* Do nothing now.  */;
  else if (DECL_CONSTRUCTOR_P (current_function_decl))
    finish_constructor_body ();
  else if (DECL_DESTRUCTOR_P (current_function_decl))
    finish_destructor_body ();
}

/* Given a function, returns the BLOCK corresponding to the outermost level
   of curly braces, skipping the artificial block created for constructor
   initializers.  */

tree
outer_curly_brace_block (tree fndecl)
{
  tree block = DECL_INITIAL (fndecl);
  if (BLOCK_OUTER_CURLY_BRACE_P (block))
    return block;
  block = BLOCK_SUBBLOCKS (block);
  if (BLOCK_OUTER_CURLY_BRACE_P (block))
    return block;
  block = BLOCK_SUBBLOCKS (block);
  gcc_assert (BLOCK_OUTER_CURLY_BRACE_P (block));
  return block;
}

/* If FNDECL is a class's key method, add the class to the list of
   keyed classes that should be emitted.  */

static void
record_key_method_defined (tree fndecl)
{
  if (DECL_NONSTATIC_MEMBER_FUNCTION_P (fndecl)
      && DECL_VIRTUAL_P (fndecl)
      && !processing_template_decl)
    {
      tree fnclass = DECL_CONTEXT (fndecl);
      if (fndecl == CLASSTYPE_KEY_METHOD (fnclass))
	vec_safe_push (keyed_classes, fnclass);
    }
}

/* Attempt to add a fix-it hint to RICHLOC suggesting the insertion
   of "return *this;" immediately before its location, using FNDECL's
   first statement (if any) to give the indentation, if appropriate.  */

static void
add_return_star_this_fixit (gcc_rich_location *richloc, tree fndecl)
{
  location_t indent = UNKNOWN_LOCATION;
  tree stmts = expr_first (DECL_SAVED_TREE (fndecl));
  if (stmts)
    indent = EXPR_LOCATION (stmts);
  richloc->add_fixit_insert_formatted ("return *this;",
				       richloc->get_loc (),
				       indent);
}

/* This function carries out the subset of finish_function operations needed
   to emit the compiler-generated outlined helper functions used by the
   coroutines implementation.  */

static void
emit_coro_helper (tree helper)
{
  /* This is a partial set of the operations done by finish_function()
     plus emitting the result.  */
  set_cfun (NULL);
  current_function_decl = helper;
  begin_scope (sk_function_parms, NULL);
  store_parm_decls (DECL_ARGUMENTS (helper));
  announce_function (helper);
  allocate_struct_function (helper, false);
  cfun->language = ggc_cleared_alloc<language_function> ();
  poplevel (1, 0, 1);
  maybe_save_constexpr_fundef (helper);
  /* We must start each function with a clear fold cache.  */
  clear_fold_cache ();
  cp_fold_function (helper);
  DECL_CONTEXT (DECL_RESULT (helper)) = helper;
  BLOCK_SUPERCONTEXT (DECL_INITIAL (helper)) = helper;
  /* This function has coroutine IFNs that we should handle in middle
     end lowering.  */
  cfun->coroutine_component = true;
  cp_genericize (helper);
  expand_or_defer_fn (helper);
}

/* Finish up a function declaration and compile that function
   all the way to assembler language output.  The free the storage
   for the function definition. INLINE_P is TRUE if we just
   finished processing the body of an in-class inline function
   definition.  (This processing will have taken place after the
   class definition is complete.)  */

tree
finish_function (bool inline_p)
{
  tree fndecl = current_function_decl;
  tree fntype, ctype = NULL_TREE;
  tree resumer = NULL_TREE, destroyer = NULL_TREE;
  bool coro_p = flag_coroutines
		&& !processing_template_decl
		&& DECL_COROUTINE_P (fndecl);
  bool coro_emit_helpers = false;

  /* When we get some parse errors, we can end up without a
     current_function_decl, so cope.  */
  if (fndecl == NULL_TREE)
    return error_mark_node;

  if (!DECL_OMP_DECLARE_REDUCTION_P (fndecl))
    finish_lambda_scope ();

  if (c_dialect_objc ())
    objc_finish_function ();

  record_key_method_defined (fndecl);

  fntype = TREE_TYPE (fndecl);

  /*  TREE_READONLY (fndecl) = 1;
      This caused &foo to be of type ptr-to-const-function
      which then got a warning when stored in a ptr-to-function variable.  */

  gcc_assert (building_stmt_list_p ());
  /* The current function is being defined, so its DECL_INITIAL should
     be set, and unless there's a multiple definition, it should be
     error_mark_node.  */
  gcc_assert (DECL_INITIAL (fndecl) == error_mark_node);

  if (coro_p)
    {
      /* Only try to emit the coroutine outlined helper functions if the
	 transforms succeeded.  Otherwise, treat errors in the same way as
	 a regular function.  */
      coro_emit_helpers = morph_fn_to_coro (fndecl, &resumer, &destroyer);

      /* We should handle coroutine IFNs in middle end lowering.  */
      cfun->coroutine_component = true;

      /* Do not try to process the ramp's EH unless outlining succeeded.  */
      if (coro_emit_helpers && use_eh_spec_block (fndecl))
	finish_eh_spec_block (TYPE_RAISES_EXCEPTIONS
			      (TREE_TYPE (fndecl)),
			      current_eh_spec_block);
    }
  else
  /* For a cloned function, we've already got all the code we need;
     there's no need to add any extra bits.  */
  if (!DECL_CLONED_FUNCTION_P (fndecl))
    {
      /* Make it so that `main' always returns 0 by default.  */
      if (DECL_MAIN_P (current_function_decl))
	finish_return_stmt (integer_zero_node);

      if (use_eh_spec_block (current_function_decl))
	finish_eh_spec_block (TYPE_RAISES_EXCEPTIONS
			      (TREE_TYPE (current_function_decl)),
			      current_eh_spec_block);
    }

  /* If we're saving up tree structure, tie off the function now.  */
  DECL_SAVED_TREE (fndecl) = pop_stmt_list (DECL_SAVED_TREE (fndecl));

  finish_fname_decls ();

  /* If this function can't throw any exceptions, remember that.  */
  if (!processing_template_decl
      && !cp_function_chain->can_throw
      && !flag_non_call_exceptions
      && !decl_replaceable_p (fndecl,
			      opt_for_fn (fndecl, flag_semantic_interposition)))
    TREE_NOTHROW (fndecl) = 1;

  /* This must come after expand_function_end because cleanups might
     have declarations (from inline functions) that need to go into
     this function's blocks.  */

  /* If the current binding level isn't the outermost binding level
     for this function, either there is a bug, or we have experienced
     syntax errors and the statement tree is malformed.  */
  if (current_binding_level->kind != sk_function_parms)
    {
      /* Make sure we have already experienced errors.  */
      gcc_assert (errorcount);

      /* Throw away the broken statement tree and extra binding
	 levels.  */
      DECL_SAVED_TREE (fndecl) = alloc_stmt_list ();

      while (current_binding_level->kind != sk_function_parms)
	{
	  if (current_binding_level->kind == sk_class)
	    pop_nested_class ();
	  else
	    poplevel (0, 0, 0);
	}
    }
  poplevel (1, 0, 1);

  /* Statements should always be full-expressions at the outermost set
     of curly braces for a function.  */
  gcc_assert (stmts_are_full_exprs_p ());

  /* If there are no return statements in a function with auto return type,
     the return type is void.  But if the declared type is something like
     auto*, this is an error.  */
  if (!processing_template_decl && FNDECL_USED_AUTO (fndecl)
      && TREE_TYPE (fntype) == DECL_SAVED_AUTO_RETURN_TYPE (fndecl))
    {
      if (is_auto (DECL_SAVED_AUTO_RETURN_TYPE (fndecl))
          && !current_function_returns_value
          && !current_function_returns_null)
	{
	  /* We haven't applied return type deduction because we haven't
             seen any return statements. Do that now.  */
	  tree node = type_uses_auto (DECL_SAVED_AUTO_RETURN_TYPE (fndecl));
	  do_auto_deduction (DECL_SAVED_AUTO_RETURN_TYPE (fndecl),
			     void_node, node, tf_warning_or_error,
                             adc_return_type);

	  apply_deduced_return_type (fndecl, void_type_node);
	  fntype = TREE_TYPE (fndecl);
	}
      else if (!current_function_returns_value
	       && !current_function_returns_null)
	{
	  error ("no return statements in function returning %qT",
		 DECL_SAVED_AUTO_RETURN_TYPE (fndecl));
	  inform (input_location, "only plain %<auto%> return type can be "
		  "deduced to %<void%>");
	}
    }

  /* Remember that we were in class scope.  */
  if (current_class_name)
    ctype = current_class_type;

  if (DECL_DELETED_FN (fndecl))
    {
      DECL_INITIAL (fndecl) = error_mark_node;
      DECL_SAVED_TREE (fndecl) = NULL_TREE;
      goto cleanup;
    }

  // If this is a concept, check that the definition is reasonable.
  if (DECL_DECLARED_CONCEPT_P (fndecl))
    check_function_concept (fndecl);

  if (flag_openmp)
    if (tree attr = lookup_attribute ("omp declare variant base",
				      DECL_ATTRIBUTES (fndecl)))
      omp_declare_variant_finalize (fndecl, attr);

  /* Complain if there's just no return statement.  */
  if ((warn_return_type
       || (cxx_dialect >= cxx14
	   && DECL_DECLARED_CONSTEXPR_P (fndecl)))
      && !VOID_TYPE_P (TREE_TYPE (fntype))
      && !dependent_type_p (TREE_TYPE (fntype))
      && !current_function_returns_value && !current_function_returns_null
      /* Don't complain if we abort or throw.  */
      && !current_function_returns_abnormally
      /* Don't complain if there's an infinite loop.  */
      && !current_function_infinite_loop
      /* Don't complain if we are declared noreturn.  */
      && !TREE_THIS_VOLATILE (fndecl)
      && !DECL_NAME (DECL_RESULT (fndecl))
      && !warning_suppressed_p (fndecl, OPT_Wreturn_type)
      /* Structor return values (if any) are set by the compiler.  */
      && !DECL_CONSTRUCTOR_P (fndecl)
      && !DECL_DESTRUCTOR_P (fndecl)
      && targetm.warn_func_return (fndecl))
    {
      gcc_rich_location richloc (input_location);
      /* Potentially add a "return *this;" fix-it hint for
	 assignment operators.  */
      if (IDENTIFIER_ASSIGN_OP_P (DECL_NAME (fndecl)))
	{
	  tree valtype = TREE_TYPE (DECL_RESULT (fndecl));
	  if (TREE_CODE (valtype) == REFERENCE_TYPE
	      && current_class_ref
	      && same_type_ignoring_top_level_qualifiers_p
		  (TREE_TYPE (valtype), TREE_TYPE (current_class_ref))
	      && global_dc->option_enabled (OPT_Wreturn_type,
					    global_dc->lang_mask,
					    global_dc->option_state))
	    add_return_star_this_fixit (&richloc, fndecl);
	}
      if (cxx_dialect >= cxx14
	  && DECL_DECLARED_CONSTEXPR_P (fndecl))
	error_at (&richloc, "no return statement in %<constexpr%> function "
			    "returning non-void");
      else if (warning_at (&richloc, OPT_Wreturn_type,
			   "no return statement in function returning "
			   "non-void"))
	suppress_warning (fndecl, OPT_Wreturn_type);
    }

  /* Lambda closure members are implicitly constexpr if possible.  */
  if (cxx_dialect >= cxx17
      && LAMBDA_TYPE_P (CP_DECL_CONTEXT (fndecl)))
    DECL_DECLARED_CONSTEXPR_P (fndecl)
      = ((processing_template_decl
	  || is_valid_constexpr_fn (fndecl, /*complain*/false))
	 && potential_constant_expression (DECL_SAVED_TREE (fndecl)));

  /* Save constexpr function body before it gets munged by
     the NRV transformation.   */
  maybe_save_constexpr_fundef (fndecl);

  /* Invoke the pre-genericize plugin before we start munging things.  */
  if (!processing_template_decl)
    invoke_plugin_callbacks (PLUGIN_PRE_GENERICIZE, fndecl);

  /* Perform delayed folding before NRV transformation.  */
  if (!processing_template_decl
      && !DECL_IMMEDIATE_FUNCTION_P (fndecl)
      && !DECL_OMP_DECLARE_REDUCTION_P (fndecl))
    cp_fold_function (fndecl);

  /* Set up the named return value optimization, if we can.  Candidate
     variables are selected in check_return_expr.  */
  if (current_function_return_value)
    {
      tree r = current_function_return_value;
      tree outer;

      if (r != error_mark_node
	  /* This is only worth doing for fns that return in memory--and
	     simpler, since we don't have to worry about promoted modes.  */
	  && aggregate_value_p (TREE_TYPE (TREE_TYPE (fndecl)), fndecl)
	  /* Only allow this for variables declared in the outer scope of
	     the function so we know that their lifetime always ends with a
	     return; see g++.dg/opt/nrv6.C.  We could be more flexible if
	     we were to do this optimization in tree-ssa.  */
	  && (outer = outer_curly_brace_block (fndecl))
	  && chain_member (r, BLOCK_VARS (outer)))
	finalize_nrv (&DECL_SAVED_TREE (fndecl), r, DECL_RESULT (fndecl));

      current_function_return_value = NULL_TREE;
    }

  /* Must mark the RESULT_DECL as being in this function.  */
  DECL_CONTEXT (DECL_RESULT (fndecl)) = fndecl;

  /* Set the BLOCK_SUPERCONTEXT of the outermost function scope to point
     to the FUNCTION_DECL node itself.  */
  BLOCK_SUPERCONTEXT (DECL_INITIAL (fndecl)) = fndecl;

  /* Store the end of the function, so that we get good line number
     info for the epilogue.  */
  cfun->function_end_locus = input_location;

  /* Complain about parameters that are only set, but never otherwise used.  */
  if (warn_unused_but_set_parameter
      && !processing_template_decl
      && errorcount == unused_but_set_errorcount
      && !DECL_CLONED_FUNCTION_P (fndecl))
    {
      tree decl;

      for (decl = DECL_ARGUMENTS (fndecl);
	   decl;
	   decl = DECL_CHAIN (decl))
	if (TREE_USED (decl)
	    && TREE_CODE (decl) == PARM_DECL
	    && !DECL_READ_P (decl)
	    && DECL_NAME (decl)
	    && !DECL_ARTIFICIAL (decl)
	    && !warning_suppressed_p (decl,OPT_Wunused_but_set_parameter)
	    && !DECL_IN_SYSTEM_HEADER (decl)
	    && TREE_TYPE (decl) != error_mark_node
	    && !TYPE_REF_P (TREE_TYPE (decl))
	    && (!CLASS_TYPE_P (TREE_TYPE (decl))
	        || !TYPE_HAS_NONTRIVIAL_DESTRUCTOR (TREE_TYPE (decl))))
	  warning_at (DECL_SOURCE_LOCATION (decl),
		      OPT_Wunused_but_set_parameter,
		      "parameter %qD set but not used", decl);
      unused_but_set_errorcount = errorcount;
    }

  /* Complain about locally defined typedefs that are not used in this
     function.  */
  maybe_warn_unused_local_typedefs ();

  /* Possibly warn about unused parameters.  */
  if (warn_unused_parameter
      && !processing_template_decl 
      && !DECL_CLONED_FUNCTION_P (fndecl))
    do_warn_unused_parameter (fndecl);

  /* Genericize before inlining.  */
  if (!processing_template_decl
      && !DECL_IMMEDIATE_FUNCTION_P (fndecl)
      && !DECL_OMP_DECLARE_REDUCTION_P (fndecl))
    cp_genericize (fndecl);

  /* Emit the resumer and destroyer functions now, providing that we have
     not encountered some fatal error.  */
  if (coro_emit_helpers)
    {
      emit_coro_helper (resumer);
      emit_coro_helper (destroyer);
    }

 cleanup:
  /* We're leaving the context of this function, so zap cfun.  It's still in
     DECL_STRUCT_FUNCTION, and we'll restore it in tree_rest_of_compilation.  */
  set_cfun (NULL);
  current_function_decl = NULL;

  /* If this is an in-class inline definition, we may have to pop the
     bindings for the template parameters that we added in
     maybe_begin_member_template_processing when start_function was
     called.  */
  if (inline_p)
    maybe_end_member_template_processing ();

  /* Leave the scope of the class.  */
  if (ctype)
    pop_nested_class ();

  --function_depth;

  /* Clean up.  */
  current_function_decl = NULL_TREE;

  invoke_plugin_callbacks (PLUGIN_FINISH_PARSE_FUNCTION, fndecl);
  return fndecl;
}

/* Create the FUNCTION_DECL for a function definition.
   DECLSPECS and DECLARATOR are the parts of the declaration;
   they describe the return type and the name of the function,
   but twisted together in a fashion that parallels the syntax of C.

   This function creates a binding context for the function body
   as well as setting up the FUNCTION_DECL in current_function_decl.

   Returns a FUNCTION_DECL on success.

   If the DECLARATOR is not suitable for a function (it defines a datum
   instead), we return 0, which tells yyparse to report a parse error.

   May return void_type_node indicating that this method is actually
   a friend.  See grokfield for more details.

   Came here with a `.pushlevel' .

   DO NOT MAKE ANY CHANGES TO THIS CODE WITHOUT MAKING CORRESPONDING
   CHANGES TO CODE IN `grokfield'.  */

tree
grokmethod (cp_decl_specifier_seq *declspecs,
	    const cp_declarator *declarator, tree attrlist)
{
  tree fndecl = grokdeclarator (declarator, declspecs, MEMFUNCDEF, 0,
				&attrlist);

  if (fndecl == error_mark_node)
    return error_mark_node;

  if (attrlist)
    cplus_decl_attributes (&fndecl, attrlist, 0);

  /* Pass friends other than inline friend functions back.  */
  if (fndecl == void_type_node)
    return fndecl;

  if (DECL_IN_AGGR_P (fndecl))
    {
      if (DECL_CLASS_SCOPE_P (fndecl))
	error ("%qD is already defined in class %qT", fndecl,
	       DECL_CONTEXT (fndecl));
      return error_mark_node;
    }

  check_template_shadow (fndecl);

  /* p1779 ABI-Isolation makes inline not a default for in-class
     definitions in named module purview.  If the user explicitly
     made it inline, grokdeclarator will already have done the right
     things.  */
  if ((!named_module_purview_p ()
       || flag_module_implicit_inline
      /* Lambda's operator function remains inline.  */
       || LAMBDA_TYPE_P (DECL_CONTEXT (fndecl)))
      /* If the user explicitly asked for this to be inline, we don't
	 need to do more, but more importantly we want to warn if we
	 can't inline it.  */
      && !DECL_DECLARED_INLINE_P (fndecl))
    {
      if (TREE_PUBLIC (fndecl))
	DECL_COMDAT (fndecl) = 1;
      DECL_DECLARED_INLINE_P (fndecl) = 1;
      /* It's ok if we can't inline this.  */
      DECL_NO_INLINE_WARNING_P (fndecl) = 1;
    }

  /* We process method specializations in finish_struct_1.  */
  if (processing_template_decl && !DECL_TEMPLATE_SPECIALIZATION (fndecl))
    {
      /* Avoid calling decl_spec_seq... until we have to.  */
      bool friendp = decl_spec_seq_has_spec_p (declspecs, ds_friend);
      fndecl = push_template_decl (fndecl, friendp);
      if (fndecl == error_mark_node)
	return fndecl;
    }

  if (DECL_CHAIN (fndecl) && !decl_spec_seq_has_spec_p (declspecs, ds_friend))
    {
      fndecl = copy_node (fndecl);
      TREE_CHAIN (fndecl) = NULL_TREE;
    }

  cp_finish_decl (fndecl, NULL_TREE, false, NULL_TREE, 0);

  DECL_IN_AGGR_P (fndecl) = 1;
  return fndecl;
}


/* VAR is a VAR_DECL.  If its type is incomplete, remember VAR so that
   we can lay it out later, when and if its type becomes complete.

   Also handle constexpr variables where the initializer involves
   an unlowered PTRMEM_CST because the class isn't complete yet.  */

void
maybe_register_incomplete_var (tree var)
{
  gcc_assert (VAR_P (var));

  /* Keep track of variables with incomplete types.  */
  if (!processing_template_decl && TREE_TYPE (var) != error_mark_node
      && DECL_EXTERNAL (var))
    {
      tree inner_type = TREE_TYPE (var);

      while (TREE_CODE (inner_type) == ARRAY_TYPE)
	inner_type = TREE_TYPE (inner_type);
      inner_type = TYPE_MAIN_VARIANT (inner_type);

      if ((!COMPLETE_TYPE_P (inner_type) && CLASS_TYPE_P (inner_type))
	  /* RTTI TD entries are created while defining the type_info.  */
	  || (TYPE_LANG_SPECIFIC (inner_type)
	      && TYPE_BEING_DEFINED (inner_type)))
	{
	  incomplete_var iv = {var, inner_type};
	  vec_safe_push (incomplete_vars, iv);
	}
      else if (!(DECL_LANG_SPECIFIC (var) && DECL_TEMPLATE_INFO (var))
	       && decl_constant_var_p (var)
	       && (TYPE_PTRMEM_P (inner_type) || CLASS_TYPE_P (inner_type)))
	{
	  /* When the outermost open class is complete we can resolve any
	     pointers-to-members.  */
	  tree context = outermost_open_class ();
	  incomplete_var iv = {var, context};
	  vec_safe_push (incomplete_vars, iv);
	}
    }
}

/* Called when a class type (given by TYPE) is defined.  If there are
   any existing VAR_DECLs whose type has been completed by this
   declaration, update them now.  */

void
complete_vars (tree type)
{
  unsigned ix;
  incomplete_var *iv;

  for (ix = 0; vec_safe_iterate (incomplete_vars, ix, &iv); )
    {
      if (same_type_p (type, iv->incomplete_type))
	{
	  tree var = iv->decl;
	  tree type = TREE_TYPE (var);

	  if (type != error_mark_node
	      && (TYPE_MAIN_VARIANT (strip_array_types (type))
		  == iv->incomplete_type))
	    {
	      /* Complete the type of the variable.  */
	      complete_type (type);
	      cp_apply_type_quals_to_decl (cp_type_quals (type), var);
	      if (COMPLETE_TYPE_P (type))
		layout_var_decl (var);
	    }

	  /* Remove this entry from the list.  */
	  incomplete_vars->unordered_remove (ix);
	}
      else
	ix++;
    }
}

/* If DECL is of a type which needs a cleanup, build and return an
   expression to perform that cleanup here.  Return NULL_TREE if no
   cleanup need be done.  DECL can also be a _REF when called from
   split_nonconstant_init_1.  */

tree
cxx_maybe_build_cleanup (tree decl, tsubst_flags_t complain)
{
  tree type;
  tree attr;
  tree cleanup;

  /* Assume no cleanup is required.  */
  cleanup = NULL_TREE;

  if (error_operand_p (decl))
    return cleanup;

  /* Handle "__attribute__((cleanup))".  We run the cleanup function
     before the destructor since the destructor is what actually
     terminates the lifetime of the object.  */
  if (DECL_P (decl))
    attr = lookup_attribute ("cleanup", DECL_ATTRIBUTES (decl));
  else
    attr = NULL_TREE;
  if (attr)
    {
      tree id;
      tree fn;
      tree arg;

      /* Get the name specified by the user for the cleanup function.  */
      id = TREE_VALUE (TREE_VALUE (attr));
      /* Look up the name to find the cleanup function to call.  It is
	 important to use lookup_name here because that is what is
	 used in c-common.cc:handle_cleanup_attribute when performing
	 initial checks on the attribute.  Note that those checks
	 include ensuring that the function found is not an overloaded
	 function, or an object with an overloaded call operator,
	 etc.; we can rely on the fact that the function found is an
	 ordinary FUNCTION_DECL.  */
      fn = lookup_name (id);
      arg = build_address (decl);
      if (!mark_used (decl, complain) && !(complain & tf_error))
	return error_mark_node;
      cleanup = cp_build_function_call_nary (fn, complain, arg, NULL_TREE);
      if (cleanup == error_mark_node)
	return error_mark_node;
    }
  /* Handle ordinary C++ destructors.  */
  type = TREE_TYPE (decl);
  if (type_build_dtor_call (type))
    {
      int flags = LOOKUP_NORMAL|LOOKUP_NONVIRTUAL|LOOKUP_DESTRUCTOR;
      tree addr;
      tree call;

      if (TREE_CODE (type) == ARRAY_TYPE)
	addr = decl;
      else
	addr = build_address (decl);

      call = build_delete (input_location, TREE_TYPE (addr), addr,
			   sfk_complete_destructor, flags, 0, complain);
      if (call == error_mark_node)
	cleanup = error_mark_node;
      else if (TYPE_HAS_TRIVIAL_DESTRUCTOR (type))
	/* Discard the call.  */;
      else if (decl_maybe_constant_destruction (decl, type)
	       && DECL_INITIALIZED_BY_CONSTANT_EXPRESSION_P (decl))
	cxx_constant_dtor (call, decl);
      else if (cleanup)
	cleanup = cp_build_compound_expr (cleanup, call, complain);
      else
	cleanup = call;
    }

  /* build_delete sets the location of the destructor call to the
     current location, even though the destructor is going to be
     called later, at the end of the current scope.  This can lead to
     a "jumpy" behavior for users of debuggers when they step around
     the end of the block.  So let's unset the location of the
     destructor call instead.  */
  protected_set_expr_location (cleanup, UNKNOWN_LOCATION);
  if (cleanup && CONVERT_EXPR_P (cleanup))
    protected_set_expr_location (TREE_OPERAND (cleanup, 0), UNKNOWN_LOCATION);

  if (cleanup
      && DECL_P (decl)
      && !lookup_attribute ("warn_unused", TYPE_ATTRIBUTES (TREE_TYPE (decl)))
      /* Treat objects with destructors as used; the destructor may do
	 something substantive.  */
      && !mark_used (decl, complain) && !(complain & tf_error))
    return error_mark_node;

  if (cleanup && cfun && !processing_template_decl
      && !expr_noexcept_p (cleanup, tf_none))
    cp_function_chain->throwing_cleanup = true;

  return cleanup;
}


/* Return the FUNCTION_TYPE that corresponds to MEMFNTYPE, which can be a
   FUNCTION_DECL, METHOD_TYPE, FUNCTION_TYPE, pointer or reference to
   METHOD_TYPE or FUNCTION_TYPE, or pointer to member function.  */

tree
static_fn_type (tree memfntype)
{
  tree fntype;
  tree args;

  if (TYPE_PTRMEMFUNC_P (memfntype))
    memfntype = TYPE_PTRMEMFUNC_FN_TYPE (memfntype);
  if (INDIRECT_TYPE_P (memfntype)
      || TREE_CODE (memfntype) == FUNCTION_DECL)
    memfntype = TREE_TYPE (memfntype);
  if (TREE_CODE (memfntype) == FUNCTION_TYPE)
    return memfntype;
  gcc_assert (TREE_CODE (memfntype) == METHOD_TYPE);
  args = TYPE_ARG_TYPES (memfntype);
  fntype = build_function_type (TREE_TYPE (memfntype), TREE_CHAIN (args));
  fntype = apply_memfn_quals (fntype, type_memfn_quals (memfntype));
  fntype = (cp_build_type_attribute_variant
	    (fntype, TYPE_ATTRIBUTES (memfntype)));
  fntype = cxx_copy_lang_qualifiers (fntype, memfntype);
  return fntype;
}

/* DECL was originally constructed as a non-static member function,
   but turned out to be static.  Update it accordingly.  */

void
revert_static_member_fn (tree decl)
{
  tree stype = static_fn_type (decl);
  cp_cv_quals quals = type_memfn_quals (stype);
  cp_ref_qualifier rqual = type_memfn_rqual (stype);

  if (quals != TYPE_UNQUALIFIED || rqual != REF_QUAL_NONE)
    stype = apply_memfn_quals (stype, TYPE_UNQUALIFIED, REF_QUAL_NONE);

  TREE_TYPE (decl) = stype;

  if (DECL_ARGUMENTS (decl))
    DECL_ARGUMENTS (decl) = DECL_CHAIN (DECL_ARGUMENTS (decl));
  DECL_STATIC_FUNCTION_P (decl) = 1;
}

/* Return which tree structure is used by T, or TS_CP_GENERIC if T is
   one of the language-independent trees.  */

enum cp_tree_node_structure_enum
cp_tree_node_structure (union lang_tree_node * t)
{
  switch (TREE_CODE (&t->generic))
    {
    case ARGUMENT_PACK_SELECT:  return TS_CP_ARGUMENT_PACK_SELECT;
    case BASELINK:		return TS_CP_BASELINK;
    case CONSTRAINT_INFO:       return TS_CP_CONSTRAINT_INFO;
    case DEFERRED_NOEXCEPT:	return TS_CP_DEFERRED_NOEXCEPT;
    case DEFERRED_PARSE:	return TS_CP_DEFERRED_PARSE;
    case IDENTIFIER_NODE:	return TS_CP_IDENTIFIER;
    case LAMBDA_EXPR:		return TS_CP_LAMBDA_EXPR;
    case BINDING_VECTOR:		return TS_CP_BINDING_VECTOR;
    case OVERLOAD:		return TS_CP_OVERLOAD;
    case PTRMEM_CST:		return TS_CP_PTRMEM;
    case STATIC_ASSERT:		return TS_CP_STATIC_ASSERT;
    case TEMPLATE_DECL:		return TS_CP_TEMPLATE_DECL;
    case TEMPLATE_INFO:		return TS_CP_TEMPLATE_INFO;
    case TEMPLATE_PARM_INDEX:	return TS_CP_TPI;
    case TRAIT_EXPR:		return TS_CP_TRAIT_EXPR;
    case USERDEF_LITERAL:	return TS_CP_USERDEF_LITERAL;
    default:			return TS_CP_GENERIC;
    }
}

/* Build the void_list_node (void_type_node having been created).  */
tree
build_void_list_node (void)
{
  tree t = build_tree_list (NULL_TREE, void_type_node);
  return t;
}

bool
cp_missing_noreturn_ok_p (tree decl)
{
  /* A missing noreturn is ok for the `main' function.  */
  return DECL_MAIN_P (decl);
}

/* Return the decl used to identify the COMDAT group into which DECL should
   be placed.  */

tree
cxx_comdat_group (tree decl)
{
  /* Virtual tables, construction virtual tables, and virtual table
     tables all go in a single COMDAT group, named after the primary
     virtual table.  */
  if (VAR_P (decl) && DECL_VTABLE_OR_VTT_P (decl))
    decl = CLASSTYPE_VTABLES (DECL_CONTEXT (decl));
  /* For all other DECLs, the COMDAT group is the mangled name of the
     declaration itself.  */
  else
    {
      while (DECL_THUNK_P (decl))
	{
	  /* If TARGET_USE_LOCAL_THUNK_ALIAS_P, use_thunk puts the thunk
	     into the same section as the target function.  In that case
	     we must return target's name.  */
	  tree target = THUNK_TARGET (decl);
	  if (TARGET_USE_LOCAL_THUNK_ALIAS_P (target)
	      && DECL_SECTION_NAME (target) != NULL
	      && DECL_ONE_ONLY (target))
	    decl = target;
	  else
	    break;
	}
    }

  return decl;
}

/* Returns the return type for FN as written by the user, which may include
   a placeholder for a deduced return type.  */

tree
fndecl_declared_return_type (tree fn)
{
  fn = STRIP_TEMPLATE (fn);
  if (FNDECL_USED_AUTO (fn))
    return DECL_SAVED_AUTO_RETURN_TYPE (fn);

  return TREE_TYPE (TREE_TYPE (fn));
}

/* Returns true iff DECL is a variable or function declared with an auto type
   that has not yet been deduced to a real type.  */

bool
undeduced_auto_decl (tree decl)
{
  if (cxx_dialect < cxx11)
    return false;
  STRIP_ANY_LOCATION_WRAPPER (decl);
  return ((VAR_OR_FUNCTION_DECL_P (decl)
	   || TREE_CODE (decl) == TEMPLATE_DECL)
	  && type_uses_auto (TREE_TYPE (decl)));
}

/* Complain if DECL has an undeduced return type.  */

bool
require_deduced_type (tree decl, tsubst_flags_t complain)
{
  if (undeduced_auto_decl (decl))
    {
      if (warning_suppressed_p (decl) && seen_error ())
	/* We probably already complained about deduction failure.  */;
      else if (complain & tf_error)
	error ("use of %qD before deduction of %<auto%>", decl);
      note_failed_type_completion_for_satisfaction (decl);
      return false;
    }
  return true;
}

/* Create a representation of the explicit-specifier with
   constant-expression of EXPR.  COMPLAIN is as for tsubst.  */

tree
build_explicit_specifier (tree expr, tsubst_flags_t complain)
{
  if (check_for_bare_parameter_packs (expr))
    return error_mark_node;

  if (instantiation_dependent_expression_p (expr))
    /* Wait for instantiation, tsubst_function_decl will handle it.  */
    return expr;

  expr = build_converted_constant_bool_expr (expr, complain);
  expr = instantiate_non_dependent_expr_sfinae (expr, complain);
  expr = cxx_constant_value (expr);
  return expr;
}

#include "gt-cp-decl.h"
