//======================================================================
//
// aes_tb.v  — AES-128 SCA Testbench
// ------------------------------------
// Drives 10,000 encryptions with a fixed key and random plaintexts.
// Dumps a full VCD for trace extraction (Phase 3).
// Writes plaintext/ciphertext pairs to data/pt_ct.csv.
//
// VULNERABILITY: No countermeasures. The sboxw/new_sboxw signals in
// aes_core carry the raw SubBytes input/output for Round 1, which is
// the primary SCA attack point.
//
// Simulation command:
//   iverilog -o aes_sim AES_128/rtl/aes_sbox.v \
//                        AES_128/rtl/aes_key_mem.v \
//                        AES_128/rtl/aes_encipher_block.v \
//                        AES_128/rtl/aes_core.v \
//                        AES_128/tb/aes_tb.v
//   vvp aes_sim
//======================================================================

`default_nettype none
`timescale 1ns/1ps

module aes_tb;

  //----------------------------------------------------------------
  // Parameters
  //----------------------------------------------------------------
  localparam CLK_HALF = 5;           // 10 ns clock period
  localparam NUM_ENCRYPTIONS = 10000;

  // Fixed 128-bit key (NIST FIPS-197 Appendix B test key)
  localparam [127:0] FIXED_KEY = 128'h2b7e151628aed2a6abf7158809cf4f3c;

  //----------------------------------------------------------------
  // DUT connections
  //----------------------------------------------------------------
  reg            clk;
  reg            reset_n;
  reg            init;
  reg            next;
  wire           ready;
  wire           result_valid;
  reg  [127:0]   block;
  wire [127:0]   result;

  // SCA leakage signals — captured in VCD
  wire [31:0]    sboxw;
  wire [31:0]    new_sboxw;
  wire [3:0]     round;

  //----------------------------------------------------------------
  // DUT instantiation
  //----------------------------------------------------------------
  aes_core dut(
    .clk          (clk),
    .reset_n      (reset_n),
    .init         (init),
    .next         (next),
    .ready        (ready),
    .result_valid (result_valid),
    .key          (FIXED_KEY),
    .block        (block),
    .result       (result),
    .sboxw        (sboxw),
    .new_sboxw    (new_sboxw),
    .round        (round)
  );

  //----------------------------------------------------------------
  // Clock generation
  //----------------------------------------------------------------
  initial clk = 0;
  always #CLK_HALF clk = ~clk;

  //----------------------------------------------------------------
  // PRNG — simple 64-bit LFSR for plaintext generation
  // Taps at bits 63,62,60,59 (maximal length)
  //----------------------------------------------------------------
  reg [63:0] lfsr;

  //----------------------------------------------------------------
  // Wait for ready — advance one cycle first so the NBA update
  // to ready_reg (triggered by next=1) has time to settle.
  // Timeout after 200 cycles to catch hangs.
  //----------------------------------------------------------------
  task wait_ready;
    integer timeout;
    begin
      timeout = 0;
      @(posedge clk);        // let ready_reg NBA settle
      while (!ready && timeout < 200) begin
        @(posedge clk);
        timeout = timeout + 1;
      end
      if (timeout >= 200) begin
        $display("ERROR: wait_ready timed out at enc_count=%0d", enc_count);
        $fclose(csv_fd);
        $finish;
      end
    end
  endtask

  //----------------------------------------------------------------
  // Main test sequence
  //----------------------------------------------------------------
  integer csv_fd;
  integer enc_count;
  reg [127:0] pt;

  initial begin
    // Open CSV for plaintext/ciphertext pairs (verify path is writable first)
    csv_fd = $fopen("data/pt_ct.csv", "w");
    if (csv_fd == 0) begin
      $display("ERROR: Cannot open data/pt_ct.csv — run simulation from project root");
      $finish;
    end
    $fwrite(csv_fd, "index,plaintext,ciphertext\n");

    // Initialise
    reset_n = 0;
    init    = 0;
    next    = 0;
    block   = 128'h0;
    lfsr    = 64'hdeadbeef_cafebabe;  // fixed seed → reproducible

    repeat(4) @(posedge clk);
    reset_n = 1;
    repeat(2) @(posedge clk);

    // --- Key initialisation ---
    @(posedge clk);
    init = 1;
    @(posedge clk);
    init = 0;
    wait_ready;

    // --- Verify NIST SP 800-38A ECB AES-128 TC1 (not captured in VCD) ---
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // PT:  6bc1bee22e409f96e93d7e117393172a
    // CT:  3ad77bb40d7a3660a89ecaf32466ef97
    block = 128'h6bc1bee22e409f96e93d7e117393172a;
    @(posedge clk);
    next = 1;
    @(posedge clk);
    next = 0;
    wait_ready;

    if (result === 128'h3ad77bb40d7a3660a89ecaf32466ef97)
      $display("NIST vector PASSED: %h", result);
    else begin
      $display("NIST vector FAILED! Got: %h", result);
      $display("  Expected:          3ad77bb40d7a3660a89ecaf32466ef97");
      $fclose(csv_fd);
      $finish;
    end

    // --- Start VCD capture here so trace[N] aligns exactly with CSV row[N] ---
    $dumpfile("data/aes_sim.vcd");
    $dumpvars(0, aes_tb);

    // --- Main loop: 10,000 random encryptions ---
    for (enc_count = 0; enc_count < NUM_ENCRYPTIONS; enc_count = enc_count + 1)
      begin
        // Advance LFSR twice to get 128 bits of pseudorandom plaintext
        lfsr = {lfsr[62:0], lfsr[63] ^ lfsr[62] ^ lfsr[60] ^ lfsr[59]};
        pt[127:64] = lfsr;
        lfsr = {lfsr[62:0], lfsr[63] ^ lfsr[62] ^ lfsr[60] ^ lfsr[59]};
        pt[63:0]   = lfsr;
        block = pt;

        @(posedge clk);
        next = 1;
        @(posedge clk);
        next = 0;
        wait_ready;

        // Write to CSV (128-bit values as 32-char hex)
        $fwrite(csv_fd, "%0d,%032h,%032h\n", enc_count, pt, result);
      end

    $display("Done: %0d encryptions completed.", NUM_ENCRYPTIONS);
    $fclose(csv_fd);
    $finish;
  end

endmodule // aes_tb

//======================================================================
// EOF aes_tb.v
//======================================================================
