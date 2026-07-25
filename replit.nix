{pkgs}: {
  deps = [
    pkgs.pkg-config
    pkgs.gcc
    pkgs.ninja
    pkgs.cmake
    pkgs.liboqs
  ];
}
