		`include "Xoodyak_Lib.sv"
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
		logic start, reset, reset_r;
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
	assign state_in = 384'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f;
	
	logic [127:0]  nonce_t, asso_data_t, key_t;
	logic [191:0] plaintext_t;
	assign plaintext_t = 192'h4142434445464748494a4b4c4d4e4f505152535455565758;  //ascii text: ABCDEFGHIJKLMNOP QRST UVWX
	
	assign key_t = 128'h303132333435363738393a3b3c3d3e3f;  //ascii text:  0123456789:;<=>? orig: nonce
	assign nonce_t= 128'h4142434445464748494a4b4c4d4e4f50;  //ascii text: ABCDEFGHIJKLMNOP orig: asso_data
	assign asso_data_t = 128'h6162636465666768696a6b6c6d6e6f70; //ascii text: abcdefghijklmnop orig: key
	assign opmode = 1'b0;
	
	
	
	logic [127:0] authdata_o;
	logic [191:0] textout_o;
	logic encdone, sqzdone;
	logic verif_dec;
  logic verif_enc;	
				
/////////////////////////////////////////////////////End fake input section///////////////////////////////////////////////////////		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/* 
	 xooround execute (
	 
				.eph1				(eph1),
				.reset      (reset),

				.start      (start),
				.state_in  (state_in), 
				.state_out 	(state_out),
				
				.xood_done 	(xood_done)
		 );
		  */
		 logic [383:0] voiddata;
		 assign voiddata = '0; 
		 logic verif_enc, verif_dec;
		 
	xoodyak testbench_enc(
			 .eph1 (eph1),
			 .reset (reset),
			 .start (start),
			
       .textin    (plaintext_t),                                        //Either plain text or cipher text depending on opmode
       .nonce   (nonce_t),
			 .assodata (asso_data_t),
       .key      (key_t),  
			 .verification_data (verif_enc),
			 .opmode (1'b0),
			 
      .authdata (authdata_o),
      .textout  (textout_o),
			.encdone  (encdone),
			.sqzdone 	(sqzdone),
			.verify (verif_enc)

    );

logic [127:0] dec_authdata;
logic [191:0] dec_text;
logic sqzdone_dec, encdone_dec;

	xoodyak testbench_dec(
			 .eph1 (eph1),
			 .reset (reset),
			 .start (sqzdone),
			
       .textin    (textout_o),                                        //Either plain text or cipher text depending on opmode
       .nonce   (nonce_t),
			 .assodata (asso_data_t),
       .key      (key_t),
			 .verification_data (authdata_o),
			 .opmode				(1'b1), 
			 
      .authdata (dec_authdata),
      .textout  (dec_text),
			.encdone  (encdone_dec), //enc and dec appear to be the same thing here.  
			.sqzdone  (sqzdone_dec),
			.verify (verif_dec)
    );




		 
		 
		 
		
		endmodule: tb_top
 
		

		