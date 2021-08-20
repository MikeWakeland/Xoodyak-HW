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
	assign plaintext_t = {192'h4d4e4f5051525354555657584142434445464748494a4b4c};/*, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c,  //ascii text: ABCDEFGHIJKLMNOP QRST UVWX
	                      192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c,
												192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c,
												 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c, 192'h4d4e4f5051525354555657584142434445464748494a4b4c,
												192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922,
												192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 192'hf2d4cafc460076aaba0f75538d03bda15f7d0b2c08355922, 
												192'h0, 192'h0, 192'h0, 192'h0, 192'h0, 192'h0, 192'h0, 192'h0, 192'h0, 192'h0, 192'h0, 192'h0, 192'h0};*/
	assign key_t = 128'h38393a3b3c3d3e3f3031323334353637;  //ascii text:  0123456789:;<=>? orig: nonce
	assign nonce_t= 128'h494a4b4c4d4e4f504142434445464748;  //ascii text: ABCDEFGHIJKLMNOP orig: asso_data
	assign asso_data_t = 352'h696162636465666768696a6b6c6d6e6f704142434445464748494a4b4c4d4e4f50303132333435363738393a; //ascii text: abcdefghijklmnopABCDEFGHIJKLMNOP0123456789:; orig: key
	//use SOFTWARE text to generate the hex values to run through hardware.  THis is much more robust.  
	
	logic[47:0][5:0] opmode_t;
	assign opmode_t = {6'h20, 6'h20, 6'h20, 6'h20, 6'h20, 6'h20,
                     6'h21, 6'h21, 6'h21, 6'h21, 6'h21, 6'h21,
										 6'h21, 6'h21, 6'h21, 6'h21, 6'h21, 6'h21,
										 6'h22, 6'h22, 6'h22, 6'h22, 6'h23, 6'h23,
										  6'h23, 6'h23, 6'h23, 6'h23, 6'h23, 6'h23, 
											6'h23, 6'h23, 6'h23, 6'h36, 6'h36, 6'h36, 
										 6'h36, 6'h36,  6'h36, 6'h36, 6'h36, 6'h36,

										 6'h26, 6'h26, 6'h26, 6'h26, 6'h26, 6'h26
										 };
										 
										 
/*

	assign opmode_t = {4'h0, 4'h0, 4'h0, 4'h0, 4'h0, 4'h0,
										 4'h1, 4'h1, 4'h1, 4'h1, 4'h1, 4'h1,
										 4'h2, 4'h2, 4'h2, 4'h2, 4'h2, 4'h2,
										 4'h3, 4'h3, 4'h3, 4'h3, 4'h3, 4'h3, 
										 4'h4, 4'h4, 4'h4, 4'h4, 4'h4, 4'h4,
										 4'h5, 4'h5, 4'h5, 4'h5, 4'h5, 4'h5, 
										 4'h6, 4'h6, 4'h6, 4'h6, 4'h6, 4'h6,
										 4'h7, 4'h7, 4'h7, 4'h7, 4'h7, 4'h7};



*/										 
										 
										 
	logic [191:0] plaintext_wire;
assign plaintext_wire = plaintext_t[opmode_ctr];	
										 
	logic [5:0] opmode_ctr, opmode_ctr_next;
initial opmode_ctr = 6'h2e;
assign opmode_ctr_next = opmode_ctr - 1;
rregs #(6) opctr (opmode_ctr, reset | (opmode_ctr == 0) ? 6'h2e : opmode_ctr_next, eph1);	
logic [3:0] opmode_wire;
assign opmode_wire=opmode_t[opmode_ctr];
	
	
	
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
              .opmode 			(opmode_t[opmode_ctr]), //MSB: continue, 0: idle, 1: initialize, 2: nonce, 3: assoc, 4: crypt, 5: decrypt, 6: squeeze, 7: ratchet.   

              .textout 			(textout_t),
              .finished 		(finished_t)
          
        );







		endmodule: tb_top
 