# This file is automatically generated.  DO NOT EDIT!
# Generated from: NetBSD: mknative-binutils,v 1.15 2023/02/07 20:37:30 christos Exp 
# Generated from: NetBSD: mknative.common,v 1.16 2018/04/15 15:13:37 christos Exp 
#
G_libbfd_la_DEPENDENCIES=elf64-x86-64.lo elfxx-x86.lo elf-ifunc.lo elf-vxworks.lo elf64.lo elf.lo elflink.lo elf-attrs.lo elf-strtab.lo elf-eh-frame.lo elf-sframe.lo dwarf1.lo dwarf2.lo elf32-i386.lo elf32.lo coff-i386.lo cofflink.lo coffgen.lo pei-i386.lo peigen.lo pe-x86_64.lo pex64igen.lo pei-x86_64.lo elf64-gen.lo elf32-gen.lo plugin.lo cpu-i386.lo cpu-iamcu.lo netbsd-core.lo archive64.lo ofiles ../libsframe/libsframe.la
G_libbfd_la_OBJECTS=archive.lo archures.lo bfd.lo bfdio.lo bfdwin.lo  cache.lo coff-bfd.lo compress.lo corefile.lo elf-properties.lo  format.lo hash.lo libbfd.lo linker.lo merge.lo opncls.lo  reloc.lo section.lo simple.lo stab-syms.lo stabs.lo syms.lo  targets.lo binary.lo ihex.lo srec.lo tekhex.lo verilog.lo
G_DEFS=-DHAVE_CONFIG_H
G_INCLUDES=
G_TDEFAULTS=-DDEFAULT_VECTOR=x86_64_elf64_vec -DSELECT_VECS='&x86_64_elf64_vec,&i386_elf32_vec,&iamcu_elf32_vec,&i386_coff_vec,&i386_pei_vec,&x86_64_pe_vec,&x86_64_pei_vec,&elf64_le_vec,&elf64_be_vec,&elf32_le_vec,&elf32_be_vec' -DSELECT_ARCHITECTURES='&bfd_i386_arch,&bfd_iamcu_arch'
G_HAVEVECS=-DHAVE_x86_64_elf64_vec -DHAVE_i386_elf32_vec -DHAVE_iamcu_elf32_vec -DHAVE_i386_coff_vec -DHAVE_i386_pei_vec -DHAVE_x86_64_pe_vec -DHAVE_x86_64_pei_vec -DHAVE_elf64_le_vec -DHAVE_elf64_be_vec -DHAVE_elf32_le_vec -DHAVE_elf32_be_vec
