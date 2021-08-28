`include "muxreglib.sv"
		
		`define SIM  //tick commands are commands to the tools.  Tells the tools that it should go to these files and grab whats in there.  

		//----------------------------------------------
		`timescale 1ns/1ps
		module tb_top ();
 
		//----------------------------------------------
 
	 localparam MAX_CLKS = 5;

	 //--clock gen
	 logic eph1; 
	 always 
			begin
					eph1  = 1'b1;
					#1; 
					eph1 = 1'b0; 
					#1; 
			end			

		int random_num;
		logic start, reset;
		initial begin
				reset  = 1;
				$display("Starting Proc Simulation");
				random_num = $random(1);
	 
				repeat(2) @(posedge eph1);
				#1 reset= '0;
		end

	
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////Bit stuffing section - fake inputs///////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
       logic  [383:0] state_in;  //Indicies: plane, lane, zed
      
       logic [383:0] state_out;
       logic xood_done, opmode; 	

 logic start_p;
  rregs #(1)  strt (start_p , ~reset , eph1); 
	assign start = ~start_p & ~reset; 
	
	logic [127:0]  nonce_t, key_t;
	logic [351:0]  asso_data_t; 
	logic [191:0] plaintext_t; //[47:0]
	
	
	
	
	// This  testbench is for cyclist key -> absorb -> absorb -> decrypt -> decrypt 
	logic [8:0][351:0] input_data_t; 
	assign plaintext_t = {192'h4d4e4f5051525354555657584142434445464748494a4b4c};
	assign key_t = 128'h38393a3b3c3d3e3f3031323334353637;  //ascii text:  0123456789:;<=>? orig: nonce
	assign nonce_t= 128'h494a4b4c4d4e4f504142434445464748;  //ascii text: ABCDEFGHIJKLMNOP orig: asso_data
	assign asso_data_t = 352'h6162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c; //ascii text: iabcdefghijkiabcdefghijkiabcdefg orig: key
	
	
	//use SOFTWARE text to generate the hex values to run through hardware.  THis is much more robust.  

	logic [191:0] plaintext, ciphertext;
assign plaintext	= (opmode_ctr > 7)? 192'h4d4e4f5051525354555657584142434445464748494a4b4c : 192'hffffffffffffffffffffffffffffffffffffffffffffffff;
assign ciphertext	= (opmode_ctr > 21)? 192'h87a06d5561b0d87c20a12db5d34783258ff75fe5d87c0e30 : 192'hbb4416e8d6ce6ef456e2be6c08ce8eccaf42fd7c33b3de1e;
	
	assign input_data_t = {
	       352'h0,  //sky input
				 352'h0,  //rat input
         352'h0,  //sqz input
         {ciphertext, 160'h0},  //dec input,
         {plaintext, 160'h0},
         352'h6162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c, //asso data
 				 {128'h494a4b4c4d4e4f504142434445464748, 224'h0}, //nonce
         {128'h38393a3b3c3d3e3f3031323334353637, 224'h0}, // key/cyclist
				 352'h0};				 //idle 

	
	logic[47:0][4:0] opmode_t;
	assign opmode_t = { 5'h0, 5'h0, 5'h0, 5'h0, 5'h0, 5'h0,
										 5'h1, 5'h1, 5'h1, 5'h1, 5'h1, 5'h1,
										 5'h3, 5'h3, 5'h3, 5'h3, 5'h3, 5'h3,
										 5'h3, 5'h3, 5'h3, 5'h8, 5'h8, 5'h8,
										 5'h8, 5'h8, 5'h8, 5'h8, 5'h8, 5'h8,
										 5'h8, 5'h8, 5'h8, 5'h8, 5'h8, 5'h8,
										 5'h8, 5'h8, 5'h8, 5'h8, 5'h4, 5'h4,
										 5'h4, 5'h4, 5'h4, 5'h4, 5'h4, 5'h4
										 }; 
										 
										 
/* 	assign opmode_t = {5'h20, 5'h20, 5'h20, 5'h20, 5'h20, 5'h20,
	                   5'h21, 5'h21, 5'h21, 5'h21, 5'h21, 5'h21,
	                   5'h23, 5'h23, 5'h23, 5'h23, 5'h23, 5'h23,
										 5'h3, 5'h3, 5'h3, 5'h3, 5'h3, 5'h3,
										 5'h5, 5'h5, 5'h5, 5'h5, 5'h5, 5'h5, 
										 5'h5, 5'h5, 5'h5, 5'h5, 5'h5, 5'h5, 	
										 5'h6, 5'h6, 5'h6, 5'h6, 5'h6, 5'h6,
										 5'h6, 5'h6, 5'h6, 5'h6, 5'h6, 5'h6
										 };										 
										  */
										 
/*
Hash initialize -> absorb -> absorb -> squeeze -> squeeze
Keyed initialize -> nonce -> absorb -> absorb -> crypt -> crypt -> squeeze(keyed mode) 
keyed initialize -> nonce -> absorb -> absorb -> squeezekey() 
	assign opmode_t = {5'h0, 5'h0, 5'h0, 5'h0, 5'h0, 5'h0,
										 5'h1, 5'h1, 5'h1, 5'h1, 5'h1, 5'h1,
										 5'h2, 5'h2, 5'h2, 5'h2, 5'h2, 5'h2,
										 5'h3, 5'h3, 5'h3, 5'h3, 5'h3, 5'h3, 
										 5'h4, 4'h4, 4'h4, 4'h4, 4'h4, 4'h4,
										 5'h5, 5'h5, 5'h5, 5'h5, 5'h5, 5'h5, 
										 5'h6, 5'h6, 5'h6, 5'h6, 5'h6, 5'h6,
										 5'h7, 5'h7, 5'h7, 5'h7, 5'h7, 5'h7};
*/										 
										 
										 
	logic [191:0] plaintext_wire;
assign plaintext_wire = plaintext_t[opmode_ctr];	
										 
	logic [5:0] opmode_ctr, opmode_ctr_next;
initial opmode_ctr = 6'h2e;
assign opmode_ctr_next = opmode_ctr - 1;
rregs #(6) opctr (opmode_ctr, reset | (opmode_ctr == 0) ? 6'h2e : opmode_ctr_next, eph1);	
logic [4:0] opmode_wire;
assign opmode_wire=opmode_t[opmode_ctr];
	
	
	logic [127:0] authdata_o;
	logic [191:0] textout_o;
	logic encdone, sqzdone;
	logic verif_dec;
  logic verif_enc;	
	logic textout_t, finished_t;
	
	logic [351:0] datainput_wire;
	
	assign datainput_wire = input_data_t[opmode_wire]; //opmode_t[opmode_ctr]
				
/////////////////////////////////////////////////////End fake input section///////////////////////////////////////////////////////		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



         xoodyak_build xoodyak_build(
              .eph1 				(eph1),
              .reset 			  (reset),
     
              .input_data   (input_data_t[opmode_wire]),
              .opmode 			(opmode_wire), //MSB: continue, 0: idle, 1: initialize, 2: nonce, 3: assoc, 4: crypt, 5: decrypt, 6: squeeze, 7: ratchet.   

              .textout 			(textout_t),
              .finished 		(finished_t)
          
        );







		endmodule: tb_top