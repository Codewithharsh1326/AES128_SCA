//======================================================================
//
// aes_core.v  [MODIFIED FOR SCA RESEARCH]
// -----------------------------------------
// AES-128 encrypt-only core, derived from secworks/aes.
//
// Changes from original:
//   - Decipher block removed (encrypt only)
//   - AES-256 path removed (128-bit only, keylen hardwired to 0)
//   - enc_sboxw, new_sboxw, enc_round_nr exposed as output ports
//     so they appear in VCD and are available for trace extraction.
//
// VULNERABILITY NOTE: The S-Box (aes_sbox.v) is a plain lookup table
// with no masking. enc_sboxw is the raw SubBytes input and new_sboxw
// is the raw SubBytes output. In Round 1, the S-Box input is
// (plaintext_byte XOR key_byte), leaking data-dependent switching
// activity directly proportional to the Hamming Weight of the output.
//
// Original author: Joachim Strombergson, Secworks Sweden AB
// License: BSD 2-Clause
//======================================================================

`default_nettype none

module aes_core(
    input  wire            clk,
    input  wire            reset_n,

    input  wire            init,   // pulse high to load key
    input  wire            next,   // pulse high to encrypt block

    output wire            ready,
    output wire            result_valid,

    input  wire [127 : 0]  key,
    input  wire [127 : 0]  block,
    output wire [127 : 0]  result,

    // SCA leakage signals — exposed for VCD trace extraction
    output wire [31 : 0]   sboxw,       // S-Box input (enc path, 4 bytes at a time)
    output wire [31 : 0]   new_sboxw,   // S-Box output
    output wire [3  : 0]   round        // current round counter (0-10)
);

  //----------------------------------------------------------------
  // Internal constants
  //----------------------------------------------------------------
  localparam CTRL_IDLE = 2'h0;
  localparam CTRL_INIT = 2'h1;
  localparam CTRL_NEXT = 2'h2;

  //----------------------------------------------------------------
  // Registers
  //----------------------------------------------------------------
  reg [1:0] aes_core_ctrl_reg;
  reg [1:0] aes_core_ctrl_new;
  reg       aes_core_ctrl_we;

  reg       result_valid_reg;
  reg       result_valid_new;
  reg       result_valid_we;

  reg       ready_reg;
  reg       ready_new;
  reg       ready_we;

  //----------------------------------------------------------------
  // Wires
  //----------------------------------------------------------------
  reg            init_state;

  wire [127 : 0] round_key;
  wire           key_ready;

  wire [3  : 0]  enc_round_nr;
  wire [127 : 0] enc_new_block;
  wire           enc_ready;
  wire [31 : 0]  enc_sboxw;

  wire [31 : 0]  keymem_sboxw;
  wire [31 : 0]  new_sboxw_w;   // internal wire from sbox

  reg  [31 : 0]  muxed_sboxw;   // routes either keymem or enc to sbox

  //----------------------------------------------------------------
  // Port assignments
  //----------------------------------------------------------------
  assign ready        = ready_reg;
  assign result       = enc_new_block;
  assign result_valid = result_valid_reg;

  // SCA outputs: always show the encipher path signals directly
  // (not the muxed version, which also carries key-schedule activity)
  assign sboxw     = enc_sboxw;
  assign new_sboxw = new_sboxw_w;
  assign round     = enc_round_nr;

  //----------------------------------------------------------------
  // Submodule instantiations
  //----------------------------------------------------------------
  aes_encipher_block enc_block(
    .clk       (clk),
    .reset_n   (reset_n),
    .next      (next),
    .keylen    (1'b0),           // hardwired AES-128
    .round     (enc_round_nr),
    .round_key (round_key),
    .sboxw     (enc_sboxw),
    .new_sboxw (new_sboxw_w),
    .block     (block),
    .new_block (enc_new_block),
    .ready     (enc_ready)
  );

  aes_key_mem keymem(
    .clk       (clk),
    .reset_n   (reset_n),
    .key       ({key, 128'h0}),  // AES-128 key lives in key[255:128]
    .keylen    (1'b0),           // hardwired AES-128
    .init      (init),
    .round     (enc_round_nr),
    .round_key (round_key),
    .ready     (key_ready),
    .sboxw     (keymem_sboxw),
    .new_sboxw (new_sboxw_w)
  );

  // Single shared S-Box instance
  aes_sbox sbox_inst(
    .sboxw     (muxed_sboxw),
    .new_sboxw (new_sboxw_w)
  );

  //----------------------------------------------------------------
  // sbox_mux: key schedule uses S-Box during init, encipher during next
  //----------------------------------------------------------------
  always @*
    begin : sbox_mux
      if (init_state)
        muxed_sboxw = keymem_sboxw;
      else
        muxed_sboxw = enc_sboxw;
    end

  //----------------------------------------------------------------
  // reg_update
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin: reg_update
      if (!reset_n)
        begin
          result_valid_reg  <= 1'b0;
          ready_reg         <= 1'b1;
          aes_core_ctrl_reg <= CTRL_IDLE;
        end
      else
        begin
          if (result_valid_we)  result_valid_reg  <= result_valid_new;
          if (ready_we)         ready_reg         <= ready_new;
          if (aes_core_ctrl_we) aes_core_ctrl_reg <= aes_core_ctrl_new;
        end
    end

  //----------------------------------------------------------------
  // aes_core_ctrl
  //----------------------------------------------------------------
  always @*
    begin : aes_core_ctrl
      init_state        = 1'b0;
      ready_new         = 1'b0;
      ready_we          = 1'b0;
      result_valid_new  = 1'b0;
      result_valid_we   = 1'b0;
      aes_core_ctrl_new = CTRL_IDLE;
      aes_core_ctrl_we  = 1'b0;

      case (aes_core_ctrl_reg)
        CTRL_IDLE:
          begin
            if (init)
              begin
                init_state        = 1'b1;
                ready_new         = 1'b0;
                ready_we          = 1'b1;
                result_valid_new  = 1'b0;
                result_valid_we   = 1'b1;
                aes_core_ctrl_new = CTRL_INIT;
                aes_core_ctrl_we  = 1'b1;
              end
            else if (next)
              begin
                init_state        = 1'b0;
                ready_new         = 1'b0;
                ready_we          = 1'b1;
                result_valid_new  = 1'b0;
                result_valid_we   = 1'b1;
                aes_core_ctrl_new = CTRL_NEXT;
                aes_core_ctrl_we  = 1'b1;
              end
          end

        CTRL_INIT:
          begin
            init_state = 1'b1;
            if (key_ready)
              begin
                ready_new         = 1'b1;
                ready_we          = 1'b1;
                aes_core_ctrl_new = CTRL_IDLE;
                aes_core_ctrl_we  = 1'b1;
              end
          end

        CTRL_NEXT:
          begin
            init_state = 1'b0;
            if (enc_ready)
              begin
                ready_new         = 1'b1;
                ready_we          = 1'b1;
                result_valid_new  = 1'b1;
                result_valid_we   = 1'b1;
                aes_core_ctrl_new = CTRL_IDLE;
                aes_core_ctrl_we  = 1'b1;
              end
          end

        default: begin end
      endcase
    end

endmodule // aes_core

//======================================================================
// EOF aes_core.v
//======================================================================
