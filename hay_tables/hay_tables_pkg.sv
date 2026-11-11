package hay_tables_pkg;
  localparam int N = 4;
  localparam string series_source [0:N-1] = '{"control.csv", "control.csv", "pulse.csv", "pulse.csv"};
  localparam string series_position [0:N-1] = '{"Soma", "Apikaler Dendrit", "Soma", "Apikaler Dendrit"};
  localparam string series_sha256 [0:N-1] = '{"c55ca9e6bd344e71e5c437d49f6a46211a9d1915a4cd67718058969fab757167", "c55ca9e6bd344e71e5c437d49f6a46211a9d1915a4cd67718058969fab757167", "e03087075554c4514ef1983718dbbc24adb28e110d85e7aa72d95fdec75ee34a", "e03087075554c4514ef1983718dbbc24adb28e110d85e7aa72d95fdec75ee34a"};
  localparam real series_samples [0:N-1] = '{4001.0, 4001.0, 4001.0, 4001.0};
  localparam real series_start_mV [0:N-1] = '{-80.0, -80.0, -80.0, -80.0};
  localparam real series_end_mV [0:N-1] = '{-76.75419881548211, -76.71796491622415, -81.29858177265115, -81.23299679579782};
  localparam real series_min_mV [0:N-1] = '{-80.01761105193195, -80.01297927832292, -81.29858177265115, -81.23299679579782};
  localparam real series_min_ms [0:N-1] = '{0.55, 0.45000000000000023, 100.00000000001417, 100.00000000001417};
  localparam real series_max_mV [0:N-1] = '{-75.09381026427505, -75.04633749640354, 28.09151104755652, 20.919225236399456};
  localparam real series_max_ms [0:N-1] = '{41.85000000000095, 41.70000000000092, 30.499999999998803, 30.5249999999988};
  localparam real series_mean_mV [0:N-1] = '{-76.31881504319666, -76.27397395690714, -67.23023109155922, -67.19397292818205};
  localparam real series_range_mV [0:N-1] = '{4.923800787656901, 4.966641781919378, 109.39009282020767, 102.15222203219727};
  localparam real series_std_mV [0:N-1] = '{1.2688125818521883, 1.270669372684394, 16.570086754747255, 16.22188399748039};
  localparam real series_duration_ms [0:N-1] = '{100.00000000001417, 100.00000000001417, 100.00000000001417, 100.00000000001417};
endpackage
