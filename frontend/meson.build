# Oracle frontend: a user-only (CONFIG_USER_ONLY) build of target/arm,
# accel/tcg and tcg, linked into one shared library. Entered from the
# hook in qemu/meson.build through an 'oracle' link to this directory, so
# all of QEMU's source sets and libraries are visible here.

foreach v : ['fs', 'host_os', 'python', 'genh', 'user_ss', 'common_ss',
             'common_all', 'target_arch', 'target_user_arch', 'target_common_arch',
             'target_common_arch_libs', 'target_stubs_arch_libs', 'emulator_link_args']
  if not is_variable(v)
    error('qemu-armm-oracle: qemu/meson.build no longer defines "@0@"; '.format(v) +
          'compare with how it builds the linux-user targets and update frontend/meson.build')
  endif
endforeach
foreach f : ['target-info-def.c', 'stubs/cpu-synchronize-state.c',
             'stubs/cpu-destroy-address-spaces.c']
  if not fs.is_file(meson.project_source_root() / f)
    error('qemu-armm-oracle: upstream file @0@ is gone; update frontend/meson.build'.format(f))
  endif
endforeach

# This directory is reached through a link (qemu/oracle, or the source copy
# that build.rs makes in OUT_DIR), so resolve it to find the project's include/.
# meson refuses include_directories() for a path that starts inside the QEMU tree.
oracle_frontend_dir = run_command(python, '-c',
  'import os, sys; print(os.path.realpath(sys.argv[1]))', meson.current_source_dir(),
  check: true).stdout().strip()
oracle_include_arg = '-I' + (oracle_frontend_dir / '..' / 'include')

oracle_config = {
  'TARGET_NAME': 'arm',
  'TARGET_ARCH': 'arm',
  'TARGET_BASE_ARCH': 'arm',
  'TARGET_ABI_DIR': 'arm',
  'TARGET_ARM': 'y',
  'TARGET_BIG_ENDIAN': 'n',
  'TARGET_LONG_BITS': '32',
  'CONFIG_USER_ONLY': 'y',
  'CONFIG_TCG': 'y',
}

oracle_config_data = configuration_data()
oracle_config_data.set('CONFIG_USER_ONLY', 1)
oracle_config_data.set('CONFIG_TCG', 1)
oracle_config_data.set('TARGET_ARCH', 'ARM')
oracle_config_data.set('TARGET_ARCH_VARIANT', 'ARM')
oracle_config_data.set('TARGET_ARM', 1)
oracle_config_data.set('TARGET_BIG_ENDIAN', 0)
oracle_config_data.set('TARGET_LONG_BITS', 32)
oracle_config_data.set_quoted('TARGET_NAME', 'arm')
oracle_config_h = configure_file(output: 'arm-oracle-config-target.h',
                                 configuration: oracle_config_data)

oracle_c_args = []
if host_os == 'windows'
  # POSIX names that user-exec.c and cpu-target.c use without a guard.
  oracle_c_args += ['-include', meson.current_source_dir() / 'win32' / 'user-compat.h']
endif

# Same sources as libuser, but compiled here so they get oracle_c_args.
oracle_user = user_ss.apply(oracle_config, strict: false)
oracle_user_lib = static_library('oracle-user',
  oracle_user.sources() + genh,
  c_args: ['-DCONFIG_USER_ONLY', '-DCOMPILING_SYSTEM_VS_USER'] + oracle_c_args,
  dependencies: oracle_user.dependencies(),
  build_by_default: false)

oracle_arch_srcs = [oracle_config_h, files(meson.project_source_root() / 'target-info-def.c')]
oracle_arch_deps = oracle_user.dependencies()
foreach ss_map : [target_user_arch, target_arch]
  if 'arm' in ss_map
    t = ss_map['arm'].apply(oracle_config, strict: false)
    oracle_arch_srcs += t.sources()
    oracle_arch_deps += t.dependencies()
  endif
endforeach

oracle_arch_srcs += files('oracle.c', 'user-glue.c', 'gdbstub-stubs.c')
# What libqemuutil's stub_ss adds only when configured with a *-user target.
oracle_arch_srcs += files(
  meson.project_source_root() / 'stubs' / 'cpu-synchronize-state.c',
  meson.project_source_root() / 'stubs' / 'cpu-destroy-address-spaces.c')
if host_os == 'windows'
  oracle_arch_srcs += files('host-win32.c')
else
  error('qemu-armm-oracle: only the Windows host layer exists so far')
endif

oracle_common = common_ss.apply(oracle_config, strict: false)
oracle_objects = [common_all.extract_objects(oracle_common.sources())]
oracle_arch_deps += oracle_common.dependencies()
oracle_common_arch = target_common_arch['arm'].apply(oracle_config, strict: false)
oracle_objects += target_common_arch_libs['arm'].extract_objects(oracle_common_arch.sources())
oracle_arch_deps += oracle_common_arch.dependencies()
oracle_objects += oracle_user_lib.extract_all_objects(recursive: false)

oracle_lib_deps = []
foreach dep : oracle_arch_deps
  oracle_lib_deps += dep.partial_dependency(compile_args: true, includes: true)
endforeach

oracle_arch_lib = static_library('oracle-arm',
  oracle_arch_srcs + genh,
  dependencies: oracle_lib_deps,
  objects: oracle_objects,
  include_directories: include_directories('../target/arm'),
  c_args: ['-DCOMPILING_PER_TARGET',
           '-DCONFIG_TARGET="arm-oracle-config-target.h"',
           '-DARMM_ORACLE_BUILD', oracle_include_arg] + oracle_c_args,
  build_by_default: false)

armm_oracle_lib = shared_library('armm_oracle',
  name_prefix: '',
  objects: oracle_arch_lib.extract_all_objects(recursive: true),
  link_with: target_stubs_arch_libs.get('arm', []),
  dependencies: oracle_arch_deps,
  link_args: emulator_link_args,
  build_by_default: false)

alias_target('armm-oracle', armm_oracle_lib)
