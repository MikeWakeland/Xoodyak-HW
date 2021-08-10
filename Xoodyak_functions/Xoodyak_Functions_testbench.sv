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
       logic[3:0] opmode_t;
 logic start_p;
  rregs #(1)  strt (start_p , ~reset , eph1); 
	assign start = ~start_p & ~reset; 
	
	logic [127:0]  nonce_t, asso_data_t, key_t;
	logic [191:0] plaintext_t;
	assign plaintext_t = 192'h4d4e4f5051525354555657584142434445464748494a4b4c;  //ascii text: ABCDEFGHIJKLMNOP QRST UVWX
	  
	assign key_t = 128'h38393a3b3c3d3e3f3031323334353637;  //ascii text:  0123456789:;<=>? orig: nonce
	assign nonce_t= 128'h494a4b4c4d4e4f504142434445464748;  //ascii text: ABCDEFGHIJKLMNOP orig: asso_data
	assign asso_data_t = 128'h696a6b6c6d6e6f706162636465666768; //ascii text: abcdefghijklmnop orig: key
	
	
	
	assign opmode_t = 4'b0;
	
	
	
	logic [127:0] authdata_o;
	logic [191:0] textout_o;
	logic encdone, sqzdone;
	logic verif_dec;
  logic verif_enc;	
	logic textout_t, finished_t;
				
/////////////////////////////////////////////////////End fake input section///////////////////////////////////////////////////////		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



         xoodyak_build xoodyak_build(
              .eph1 				(eph1),
              .reset 			  (reset),
              .start			  (start),
          
              .textin  		  (plaintext_t),//Either plain text or cipher text depending on opmode
              .nonce 				(nonce_t),
              .assodata 		(asso_data_t),
              .key 					(key_t),
              .opmode 			(opmode_t), //MSB: continue, 0: idle, 1: initialize, 2: nonce, 3: assoc, 4: crypt, 5: decrypt, 6: squeeze, 7: ratchet.   

              .textout 			(textout_t),
              .finished 		(finished_t)
          
        );







		endmodule: tb_top
 