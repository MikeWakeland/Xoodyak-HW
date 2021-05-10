/**********************************
CONTENTS
  registers
  muxes


  rlzenc_x32
  rdecode_4_16

************************************/


//-----------------------------------
//--the most basic register
//-----------------------------------
module rregs #(parameter width=1) (
    output logic [width-1:0] q,
    input  logic [width-1:0] d,
    input  logic clk
);
    always_ff @(posedge clk) q <= d;
endmodule:rregs

//-----------------------------------
//--the most basic register using typedef items
//-----------------------------------
module rregt #(parameter type T=logic) (
    output T q,  //
    input  T d,  //													
    input  logic  clk
);
    logic [$bits(d)-1:0] qtmp;
    rregs #($bits(d))    rg ( qtmp, d, clk );
    assign q = T'(qtmp);
endmodule

//-----------------------------------
//--a clock enabled register, but implemented as a mux-reg since fpga doesn't do clk enable
//-----------------------------------
module rregs_en #(parameter width=1, usemux = 1) ( //#(parameter width=1) ( 
    output logic [width-1:0] q,
    input  logic [width-1:0] d,
    input  logic clk,
    input  logic clk_en
);
    logic  [width-1:0] dt;
    assign dt = clk_en ? d : q;  
    always_ff @(posedge clk) q <= dt;
endmodule:rregs_en

//-----------------------------------
//--set dominate set-reset register
//-----------------------------------
module rregs_sr #(parameter width = 1)
                (output logic [width-1:0] q,
                 input  logic [width-1:0] set,
                 input  logic             rst,
                 input  logic             clk);

rregs #(width) r1 (q, set ? '1 : (rst ? '0 : q), clk);
endmodule:rregs_sr

//-----------------------------------
//--reset dominate set-reset register, note parameter are in same place as rregs_sr
//-----------------------------------
module rregs_rs #(parameter width = 1)
                (output logic [width-1:0] q,
                 input  logic [width-1:0] set,
                 input  logic             rst,
                 input  logic             clk);

rregs #(width) r1 (q, rst ? '0 : (set ? '1 : q), clk);
endmodule:rregs_rs

//-----------------------------------
//--3:1 one-hot mux
//-----------------------------------
module rmuxdx2_im #(parameter width=1) (
  output logic [width-1:0] out,
  input  logic             sel0, 
  input  logic [width-1:0] in0,
  input  logic             sel1, 
  input  logic [width-1:0] in1
);
  always_comb begin
  unique casez(1'b1) // synopsys infer_onehot_mux
    sel0 : out = in0;
    sel1 : out = in1;
    default : out = 'X;
  endcase
  end
endmodule:rmuxdx2_im

module rmuxdx3_im #(parameter width=1) (
  output logic [width-1:0] out,
  input  logic             sel0, 
  input  logic [width-1:0] in0,
  input  logic             sel1, 
  input  logic [width-1:0] in1, 
  input  logic             sel2, 
  input  logic [width-1:0] in2
);
  always_comb begin
  unique casez(1'b1) // synopsys infer_onehot_mux
    sel0 : out = in0;
    sel1 : out = in1;
    sel2 : out = in2;
    default : out = 'X;
  endcase
  end
endmodule:rmuxdx3_im

//-----------------------------------
//--3:1 one-hot mux with default output
//-----------------------------------
module rmuxd3_im #(parameter width=1) (
  output logic [width-1:0] out,
  input  logic             sel0, 
  input  logic [width-1:0] in0,
  input  logic             sel1, 
  input  logic [width-1:0] in1, 
  input  logic [width-1:0] in2
);
  always_comb begin
  unique casez(1'b1) // synopsys infer_onehot_mux
    sel0 : out = in0;
    sel1 : out = in1;
    default : out = in2;
  endcase
  end
endmodule:rmuxd3_im

//--more useful muxes ---------------------------

    //-----------------------------------
    module rmuxdx4_im #(parameter width=1) (
      output logic [width-1:0] out,
      input  logic             sel0, 
      input  logic [width-1:0] in0,
      input  logic             sel1, 
      input  logic [width-1:0] in1, 
      input  logic             sel2, 
      input  logic [width-1:0] in2,
      input  logic             sel3, 
      input  logic [width-1:0] in3
    );
      always_comb begin
      unique casez(1'b1) // synopsys infer_onehot_mux
        sel0 : out = in0;
        sel1 : out = in1;
        sel2 : out = in2;
        sel3 : out = in3;
        default : out = 'X;
      endcase
      end
    endmodule:rmuxdx4_im
    
    //-----------------------------------
    module rmuxd4_im #(parameter width=1) (
      output logic [width-1:0] out,
      input  logic             sel0, 
      input  logic [width-1:0] in0,
      input  logic             sel1, 
      input  logic [width-1:0] in1, 
      input  logic             sel2, 
      input  logic [width-1:0] in2,
      input  logic [width-1:0] in3
    );
      always_comb begin
      unique casez(1'b1) // synopsys infer_onehot_mux
        sel0 : out = in0;
        sel1 : out = in1;
        sel2 : out = in2;
        default : out = in3;
      endcase
      end
    endmodule:rmuxd4_im
    
    //-----------------------------------
    module rmuxdx5_im #(parameter width=1) (
      output logic [width-1:0] out,
      input  logic             sel0, 
      input  logic [width-1:0] in0,
      input  logic             sel1, 
      input  logic [width-1:0] in1, 
      input  logic             sel2, 
      input  logic [width-1:0] in2,
      input  logic             sel3, 
      input  logic [width-1:0] in3,
      input  logic             sel4, 
      input  logic [width-1:0] in4
    );
      always_comb begin
      unique casez(1'b1) // synopsys infer_onehot_mux
        sel0 : out = in0;
        sel1 : out = in1;
        sel2 : out = in2;
        sel3 : out = in3;
        sel4 : out = in4;
        default : out = 'X;
      endcase
      end
    endmodule:rmuxdx5_im
	
    //-----------------------------------	
	
	    module rmuxd5_im #(parameter width=1) (
      output logic [width-1:0] out,
      input  logic             sel0, 
      input  logic [width-1:0] in0,
      input  logic             sel1, 
      input  logic [width-1:0] in1, 
      input  logic             sel2, 
      input  logic [width-1:0] in2,
	  input  logic 			   sel3,
      input  logic [width-1:0] in3,
	  input  logic [width-1:0] in4
    );
      always_comb begin
      unique casez(1'b1) // synopsys infer_onehot_mux
        sel0 : out = in0;
        sel1 : out = in1;
        sel2 : out = in2;
		sel3 : out = in3;
        default : out = in4;
      endcase
      end
    endmodule:rmuxd5_im
	
	
	
	
    //-----------------------------------
    module rmuxdx6_im #(parameter width=1) (
      output logic [width-1:0] out,
      input  logic             sel0, 
      input  logic [width-1:0] in0,
      input  logic             sel1, 
      input  logic [width-1:0] in1, 
      input  logic             sel2, 
      input  logic [width-1:0] in2,
      input  logic             sel3, 
      input  logic [width-1:0] in3,
      input  logic             sel4, 
      input  logic [width-1:0] in4,
      input  logic             sel5, 
      input  logic [width-1:0] in5
    );
      always_comb begin
      unique casez(1'b1) // synopsys infer_onehot_mux
        sel0 : out = in0;
        sel1 : out = in1;
        sel2 : out = in2;
        sel3 : out = in3;
        sel4 : out = in4;
        sel5 : out = in5;
        default : out = 'X;
      endcase
      end
    endmodule:rmuxdx6_im
	
    //-----------------------------------
	
	  module rmuxd6_im #(parameter width=1) (
      output logic [width-1:0] out,
      input  logic             sel0, 
      input  logic [width-1:0] in0,
      input  logic             sel1, 
      input  logic [width-1:0] in1, 
      input  logic             sel2, 
      input  logic [width-1:0] in2,
	  input  logic 			   sel3,
      input  logic [width-1:0] in3,
	  input  logic			   sel4,
	  input  logic [width-1:0] in4,
	  input  logic [width-1:0] in5
    );
      always_comb begin
      unique casez(1'b1) // synopsys infer_onehot_mux
        sel0 : out = in0;
        sel1 : out = in1;
        sel2 : out = in2;
		sel3 : out = in3;
		sel4 : out = in4;
        default : out = in5;
      endcase
      end
    endmodule:rmuxd6_im
	
	
	
	
    //-----------------------------------
	
	

	module rmuxdx7_im #(parameter width=1) (
      output logic [width-1:0] out,
      input  logic             sel0, 
      input  logic [width-1:0] in0,
      input  logic             sel1, 
      input  logic [width-1:0] in1, 
      input  logic             sel2, 
      input  logic [width-1:0] in2,
      input  logic             sel3, 
      input  logic [width-1:0] in3,
      input  logic             sel4, 
      input  logic [width-1:0] in4,
      input  logic             sel5, 
      input  logic [width-1:0] in5,
      input  logic             sel6, 
      input  logic [width-1:0] in6	  
    );
      always_comb begin
      unique casez(1'b1) // synopsys infer_onehot_mux
        sel0 : out = in0;
        sel1 : out = in1;
        sel2 : out = in2;
        sel3 : out = in3;
        sel4 : out = in4;
        sel5 : out = in5;
				sel6 : out = in6;
        default : out = 'X;
      endcase
      end
    endmodule:rmuxdx7_im

    //-----------------------------------
	
    module rmuxd7_im #(parameter width=1) (
      output logic [width-1:0] out,
      input  logic             sel0, 
      input  logic [width-1:0] in0,
      input  logic             sel1, 
      input  logic [width-1:0] in1, 
      input  logic             sel2, 
      input  logic [width-1:0] in2,
	  input  logic 			   sel3,
      input  logic [width-1:0] in3,
      input  logic             sel4, 
      input  logic [width-1:0] in4, 
      input  logic             sel5, 
      input  logic [width-1:0] in5,  
	  input  logic [width-1:0] in6
    );
      always_comb begin
      unique casez(1'b1) // synopsys infer_onehot_mux
        sel0 : out = in0;
        sel1 : out = in1;
        sel2 : out = in2;
		sel3 : out = in3;
		sel4 : out = in4;
        sel5 : out = in5;	
        default : out = in6;
      endcase
      end
    endmodule:rmuxd7_im		
		
    //---------------------------------
    module rdecode_4_16 (
        output logic [15:0]  out,
        input  logic [3:0]   in
    ) ;
        assign out[0] =  ~in[3] & ~in[2] & ~in[1] & ~in[0];
        assign out[1] =  ~in[3] & ~in[2] & ~in[1] &  in[0];
        assign out[2] =  ~in[3] & ~in[2] &  in[1] & ~in[0];
        assign out[3] =  ~in[3] & ~in[2] &  in[1] &  in[0];
        assign out[4] =  ~in[3] &  in[2] & ~in[1] & ~in[0];
        assign out[5] =  ~in[3] &  in[2] & ~in[1] &  in[0];
        assign out[6] =  ~in[3] &  in[2] &  in[1] & ~in[0];
        assign out[7] =  ~in[3] &  in[2] &  in[1] &  in[0];
        assign out[8] =   in[3] & ~in[2] & ~in[1] & ~in[0];
        assign out[9] =   in[3] & ~in[2] & ~in[1] &  in[0];
        assign out[10] =  in[3] & ~in[2] &  in[1] & ~in[0];
        assign out[11] =  in[3] & ~in[2] &  in[1] &  in[0];
        assign out[12] =  in[3] &  in[2] & ~in[1] & ~in[0];
        assign out[13] =  in[3] &  in[2] & ~in[1] &  in[0];
        assign out[14] =  in[3] &  in[2] &  in[1] & ~in[0];
        assign out[15] =  in[3] &  in[2] & 	in[1] &  in[0];
    endmodule: rdecode_4_16
//---------------------------------


    module rdecode_5_32 (
        output logic [31:0]  out,
        input  logic [4:0]   in
    ) ;
        assign out[0]  = ~in[4] & ~in[3] & ~in[2] & ~in[1] & ~in[0];
        assign out[1]  = ~in[4] & ~in[3] & ~in[2] & ~in[1] &  in[0];
        assign out[2]  = ~in[4] & ~in[3] & ~in[2] &  in[1] & ~in[0];
        assign out[3]  = ~in[4] & ~in[3] & ~in[2] &  in[1] &  in[0];
        assign out[4]  = ~in[4] & ~in[3] &  in[2] & ~in[1] & ~in[0];
        assign out[5]  = ~in[4] & ~in[3] &  in[2] & ~in[1] &  in[0];
        assign out[6]  = ~in[4] & ~in[3] &  in[2] &  in[1] & ~in[0];
        assign out[7]  = ~in[4] & ~in[3] &  in[2] &  in[1] &  in[0];
        assign out[8]  = ~in[4] &  in[3] & ~in[2] & ~in[1] & ~in[0];
        assign out[9]  = ~in[4] &  in[3] & ~in[2] & ~in[1] &  in[0];
        assign out[10] = ~in[4] & in[3] & ~in[2] &  in[1] & ~in[0];
        assign out[11] = ~in[4] & in[3] & ~in[2] &  in[1] &  in[0];
        assign out[12] = ~in[4] & in[3] &  in[2] & ~in[1] & ~in[0];
        assign out[13] = ~in[4] & in[3] &  in[2] & ~in[1] &  in[0];
        assign out[14] = ~in[4] & in[3] &  in[2] &  in[1] & ~in[0];
        assign out[15] = ~in[4] & in[3] &  in[2] &  in[1] &  in[0];		
        assign out[16]  = in[4] & ~in[3] & ~in[2] & ~in[1] & ~in[0];
        assign out[17]  = in[4] & ~in[3] & ~in[2] & ~in[1] &  in[0];
        assign out[18]  = in[4] & ~in[3] & ~in[2] &  in[1] & ~in[0];
        assign out[19]  = in[4] & ~in[3] & ~in[2] &  in[1] &  in[0];
        assign out[20]  = in[4] & ~in[3] &  in[2] & ~in[1] & ~in[0];
        assign out[21]  = in[4] & ~in[3] &  in[2] & ~in[1] &  in[0];
        assign out[22]  = in[4] & ~in[3] &  in[2] &  in[1] & ~in[0];
        assign out[23]  = in[4] & ~in[3] &  in[2] &  in[1] &  in[0];
        assign out[24]  = in[4] &  in[3] & ~in[2] & ~in[1] & ~in[0];
        assign out[25]  = in[4] &  in[3] & ~in[2] & ~in[1] &  in[0];
        assign out[26]  = in[4] & in[3] & ~in[2] &  in[1] & ~in[0];
        assign out[27]  = in[4] & in[3] & ~in[2] &  in[1] &  in[0];
        assign out[28]  = in[4] & in[3] &  in[2] & ~in[1] & ~in[0];
        assign out[29]  = in[4] & in[3] &  in[2] & ~in[1] &  in[0];
        assign out[30]  = in[4] & in[3] &  in[2] &  in[1] & ~in[0];
        assign out[31]  = in[4] & in[3] &  in[2] &  in[1] &  in[0];			
    endmodule: rdecode_5_32
	
//---------------------------------






//=====================================
module rf_2r1w_32x32 (

   output logic [31:0]   rddata0_p,
   output logic [31:0]   rddata1_p,
   input  logic [4:0]    rdaddr0_p,
   input  logic          rden0_p,

   input  logic [4:0]    rdaddr1_p,
   input  logic          rden1_p,

   input  logic [31:0]   wrdata0_p,
   input  logic [4:0]    wraddr0_p,
   input  logic          wren0_p,
   input  clk

);

  wire [31:0] ent0_p, wrent0_p ;
  wire [31:0] ent1_p, wrent1_p ;
  wire [31:0] ent2_p, wrent2_p ;
  wire [31:0] ent3_p, wrent3_p ;
  wire [31:0] ent4_p, wrent4_p ;
  wire [31:0] ent5_p, wrent5_p ;
  wire [31:0] ent6_p, wrent6_p ;
  wire [31:0] ent7_p, wrent7_p ;
  wire [31:0] ent8_p, wrent8_p ;
  wire [31:0] ent9_p, wrent9_p ;
  wire [31:0] ent10_p, wrent10_p ;
  wire [31:0] ent11_p, wrent11_p ;
  wire [31:0] ent12_p, wrent12_p ;
  wire [31:0] ent13_p, wrent13_p ;
  wire [31:0] ent14_p, wrent14_p ;
  wire [31:0] ent15_p, wrent15_p ;
  wire [31:0] ent16_p, wrent16_p ;
  wire [31:0] ent17_p, wrent17_p ;
  wire [31:0] ent18_p, wrent18_p ;
  wire [31:0] ent19_p, wrent19_p ;
  wire [31:0] ent20_p, wrent20_p ;
  wire [31:0] ent21_p, wrent21_p ;
  wire [31:0] ent22_p, wrent22_p ;
  wire [31:0] ent23_p, wrent23_p ;
  wire [31:0] ent24_p, wrent24_p ;
  wire [31:0] ent25_p, wrent25_p ;
  wire [31:0] ent26_p, wrent26_p ;
  wire [31:0] ent27_p, wrent27_p ;
  wire [31:0] ent28_p, wrent28_p ;
  wire [31:0] ent29_p, wrent29_p ;
  wire [31:0] ent30_p, wrent30_p ;
  wire [31:0] ent31_p, wrent31_p ;

//--------------------------------------------------------------
//--------------------------------------------------------------

//--------------------------------------------------------------
// Write logic
//--------------------------------------------------------------
wire [31:0] wren_ent_p ;


   wire [31:0] wraddrdec0_p, wraddrdecuq0_p;
         rdecode_5_32 wr0 (wraddrdecuq0_p, wraddr0_p);
   assign wraddrdec0_p = wraddrdecuq0_p & {32{wren0_p}};

assign wren_ent_p =
        wraddrdec0_p              ; 

//--------------------------------------------------------------
// Storage
//--------------------------------------------------------------
      assign wrent0_p = wrdata0_p;
      assign wrent1_p = wrdata0_p;
      assign wrent2_p = wrdata0_p;
      assign wrent3_p = wrdata0_p;
      assign wrent4_p = wrdata0_p;
      assign wrent5_p = wrdata0_p;
      assign wrent6_p = wrdata0_p;
      assign wrent7_p = wrdata0_p;
      assign wrent8_p = wrdata0_p;
      assign wrent9_p = wrdata0_p;
      assign wrent10_p = wrdata0_p;
      assign wrent11_p = wrdata0_p;
      assign wrent12_p = wrdata0_p;
      assign wrent13_p = wrdata0_p;
      assign wrent14_p = wrdata0_p;
      assign wrent15_p = wrdata0_p;
      assign wrent16_p = wrdata0_p;
      assign wrent17_p = wrdata0_p;
      assign wrent18_p = wrdata0_p;
      assign wrent19_p = wrdata0_p;
      assign wrent20_p = wrdata0_p;
      assign wrent21_p = wrdata0_p;
      assign wrent22_p = wrdata0_p;
      assign wrent23_p = wrdata0_p;
      assign wrent24_p = wrdata0_p;
      assign wrent25_p = wrdata0_p;
      assign wrent26_p = wrdata0_p;
      assign wrent27_p = wrdata0_p;
      assign wrent28_p = wrdata0_p;
      assign wrent29_p = wrdata0_p;
      assign wrent30_p = wrdata0_p;
      assign wrent31_p = wrdata0_p;

						rregs_en #(32) ent0 (ent0_p, wrent0_p, clk, wren_ent_p[0]);
            rregs_en #(32) ent1 (ent1_p, wrent1_p, clk, wren_ent_p[1]);
            rregs_en #(32) ent2 (ent2_p, wrent2_p, clk, wren_ent_p[2]);
            rregs_en #(32) ent3 (ent3_p, wrent3_p, clk, wren_ent_p[3]);
            rregs_en #(32) ent4 (ent4_p, wrent4_p, clk, wren_ent_p[4]);
            rregs_en #(32) ent5 (ent5_p, wrent5_p, clk, wren_ent_p[5]);
            rregs_en #(32) ent6 (ent6_p, wrent6_p, clk, wren_ent_p[6]);
            rregs_en #(32) ent7 (ent7_p, wrent7_p, clk, wren_ent_p[7]);
            rregs_en #(32) ent8 (ent8_p, wrent8_p, clk, wren_ent_p[8]);
            rregs_en #(32) ent9 (ent9_p, wrent9_p, clk, wren_ent_p[9]);
            rregs_en #(32) ent10 (ent10_p, wrent10_p, clk, wren_ent_p[10]);
            rregs_en #(32) ent11 (ent11_p, wrent11_p, clk, wren_ent_p[11]);
            rregs_en #(32) ent12 (ent12_p, wrent12_p, clk, wren_ent_p[12]);
            rregs_en #(32) ent13 (ent13_p, wrent13_p, clk, wren_ent_p[13]);
            rregs_en #(32) ent14 (ent14_p, wrent14_p, clk, wren_ent_p[14]);
            rregs_en #(32) ent15 (ent15_p, wrent15_p, clk, wren_ent_p[15]);
            rregs_en #(32) ent16 (ent16_p, wrent16_p, clk, wren_ent_p[16]);
            rregs_en #(32) ent17 (ent17_p, wrent17_p, clk, wren_ent_p[17]);
            rregs_en #(32) ent18 (ent18_p, wrent18_p, clk, wren_ent_p[18]);
            rregs_en #(32) ent19 (ent19_p, wrent19_p, clk, wren_ent_p[19]);
            rregs_en #(32) ent20 (ent20_p, wrent20_p, clk, wren_ent_p[20]);
            rregs_en #(32) ent21 (ent21_p, wrent21_p, clk, wren_ent_p[21]);
            rregs_en #(32) ent22 (ent22_p, wrent22_p, clk, wren_ent_p[22]);
            rregs_en #(32) ent23 (ent23_p, wrent23_p, clk, wren_ent_p[23]);
            rregs_en #(32) ent24 (ent24_p, wrent24_p, clk, wren_ent_p[24]);
            rregs_en #(32) ent25 (ent25_p, wrent25_p, clk, wren_ent_p[25]);
            rregs_en #(32) ent26 (ent26_p, wrent26_p, clk, wren_ent_p[26]);
            rregs_en #(32) ent27 (ent27_p, wrent27_p, clk, wren_ent_p[27]);
            rregs_en #(32) ent28 (ent28_p, wrent28_p, clk, wren_ent_p[28]);
            rregs_en #(32) ent29 (ent29_p, wrent29_p, clk, wren_ent_p[29]);
            rregs_en #(32) ent30 (ent30_p, wrent30_p, clk, wren_ent_p[30]);
            rregs_en #(32) ent31 (ent31_p, wrent31_p, clk, wren_ent_p[31]);

//--------------------------------------------------------------
// Read logic
//--------------------------------------------------------------
   wire [4:0]    rdaddrstg0_p   ,   rdaddrstg1_p  ;
   wire [31:0]    rdsel0_p   ,   rdsel1_p  ;

   rregs_en #(5) ra0 (rdaddrstg0_p, rdaddr0_p, clk, rden0_p);
   rregs_en #(1) re0 (rden0_stg_p, rden0_p, clk, 1'b1);
   rregs_en #(5) ra1 (rdaddrstg1_p, rdaddr1_p, clk, rden1_p);
   rregs_en #(1) re1 (rden1_stg_p, rden1_p, clk, 1'b1);

   rdecode_5_32 rd0 (rdsel0_p, rdaddrstg0_p);
   rdecode_5_32 rd1 (rdsel1_p, rdaddrstg1_p);

    wire [31:0] raw_rddata0_p =
       {32{rdsel0_p[0]}} & ent0_p        | 
       {32{rdsel0_p[1]}} & ent1_p        | 
       {32{rdsel0_p[2]}} & ent2_p        | 
       {32{rdsel0_p[3]}} & ent3_p        | 
       {32{rdsel0_p[4]}} & ent4_p        | 
       {32{rdsel0_p[5]}} & ent5_p        | 
       {32{rdsel0_p[6]}} & ent6_p        | 
       {32{rdsel0_p[7]}} & ent7_p        | 
       {32{rdsel0_p[8]}} & ent8_p        | 
       {32{rdsel0_p[9]}} & ent9_p        | 
       {32{rdsel0_p[10]}} & ent10_p        | 
       {32{rdsel0_p[11]}} & ent11_p        | 
       {32{rdsel0_p[12]}} & ent12_p        | 
       {32{rdsel0_p[13]}} & ent13_p        | 
       {32{rdsel0_p[14]}} & ent14_p        | 
       {32{rdsel0_p[15]}} & ent15_p        | 
       {32{rdsel0_p[16]}} & ent16_p        | 
       {32{rdsel0_p[17]}} & ent17_p        | 
       {32{rdsel0_p[18]}} & ent18_p        | 
       {32{rdsel0_p[19]}} & ent19_p        | 
       {32{rdsel0_p[20]}} & ent20_p        | 
       {32{rdsel0_p[21]}} & ent21_p        | 
       {32{rdsel0_p[22]}} & ent22_p        | 
       {32{rdsel0_p[23]}} & ent23_p        | 
       {32{rdsel0_p[24]}} & ent24_p        | 
       {32{rdsel0_p[25]}} & ent25_p        | 
       {32{rdsel0_p[26]}} & ent26_p        | 
       {32{rdsel0_p[27]}} & ent27_p        | 
       {32{rdsel0_p[28]}} & ent28_p        | 
       {32{rdsel0_p[29]}} & ent29_p        | 
       {32{rdsel0_p[30]}} & ent30_p        | 
       {32{rdsel0_p[31]}} & ent31_p        ; 
    wire [31:0] raw_rddata1_p =
       {32{rdsel1_p[0]}} & ent0_p        | 
       {32{rdsel1_p[1]}} & ent1_p        | 
       {32{rdsel1_p[2]}} & ent2_p        | 
       {32{rdsel1_p[3]}} & ent3_p        | 
       {32{rdsel1_p[4]}} & ent4_p        | 
       {32{rdsel1_p[5]}} & ent5_p        | 
       {32{rdsel1_p[6]}} & ent6_p        | 
       {32{rdsel1_p[7]}} & ent7_p        | 
       {32{rdsel1_p[8]}} & ent8_p        | 
       {32{rdsel1_p[9]}} & ent9_p        | 
       {32{rdsel1_p[10]}} & ent10_p        | 
       {32{rdsel1_p[11]}} & ent11_p        | 
       {32{rdsel1_p[12]}} & ent12_p        | 
       {32{rdsel1_p[13]}} & ent13_p        | 
       {32{rdsel1_p[14]}} & ent14_p        | 
       {32{rdsel1_p[15]}} & ent15_p        | 
       {32{rdsel1_p[16]}} & ent16_p        | 
       {32{rdsel1_p[17]}} & ent17_p        | 
       {32{rdsel1_p[18]}} & ent18_p        | 
       {32{rdsel1_p[19]}} & ent19_p        | 
       {32{rdsel1_p[20]}} & ent20_p        | 
       {32{rdsel1_p[21]}} & ent21_p        | 
       {32{rdsel1_p[22]}} & ent22_p        | 
       {32{rdsel1_p[23]}} & ent23_p        | 
       {32{rdsel1_p[24]}} & ent24_p        | 
       {32{rdsel1_p[25]}} & ent25_p        | 
       {32{rdsel1_p[26]}} & ent26_p        | 
       {32{rdsel1_p[27]}} & ent27_p        | 
       {32{rdsel1_p[28]}} & ent28_p        | 
       {32{rdsel1_p[29]}} & ent29_p        | 
       {32{rdsel1_p[30]}} & ent30_p        | 
       {32{rdsel1_p[31]}} & ent31_p        ; 

    assign rddata0_p = rden0_stg_p ? raw_rddata0_p : {32{1'b1}};
    assign rddata1_p = rden1_stg_p ? raw_rddata1_p : {32{1'b1}};
	


endmodule:rf_2r1w_32x32



//-------------------------------------------------
//--1-read-or-write ram NO byte enables ---------Behavioral, not hardware.
//-------------------------------------------------
module rf_1rw #(parameter DEPTH=8, WIDTH=32) (
     output logic[WIDTH-1:0]         dout,
     input  logic		                 eph1,
     input  logic                    write,
     input  logic[$clog2(DEPTH)-1:0] addr,
     input  logic[WIDTH-1:0]         din );

localparam NBYTES = WIDTH/8;
localparam DLG2   = $clog2(DEPTH);


logic[NBYTES-1:0][7:0] RAM  [DEPTH-1:0]; logic[NBYTES-1:0][7:0] din_bytes;

logic[WIDTH/8-1:0] wben;
assign wben = '1;

assign din_bytes = din;

for (genvar d=0; d<DEPTH; d+=1) begin: g_rf
     for (genvar b=0; b<NBYTES; b+=1) begin : g_bytes
         rregs_en #(8) rgdata ( RAM[d][b], din_bytes[b], eph1, write & wben[b] & addr == d );
     end : g_bytes
end : g_rf

logic[DLG2-1:0] addr_stg;
rregs #(DLG2) rgaddrstg (addr_stg, addr, eph1 );

always_comb begin
     dout = '1;
     for (int i=0; i<DEPTH; i+=1) begin
         dout &= (addr_stg == i) ? RAM[i] : '1;
     end
end

endmodule: rf_1rw


//This is a counter that I ripped off the internet.  Behavioral.  
module counter(
		output logic [3:0] count_out,
    input  logic [3:0] count_in,
		input  logic clk    
);

always @(posedge clk) count_out <= count_in + 1;     //     always_ff @(posedge clk) q <= d;
endmodule: counter




