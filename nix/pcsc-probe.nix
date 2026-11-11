{
  runCommandCC,
  pkg-config,
  pcsclite,
}:

runCommandCC "pcsc-probe"
  {
    nativeBuildInputs = [ pkg-config ];
    buildInputs = [ pcsclite ];
    meta.mainProgram = "pcsc-probe";
  }
  ''
    mkdir -p $out/bin
    $CC ${./pcsc-probe.c} $(pkg-config --cflags --libs libpcsclite) -o $out/bin/pcsc-probe
  ''
