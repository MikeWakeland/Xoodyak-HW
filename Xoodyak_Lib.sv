//The start flags don't actually do anything.  Instead wires propogate directly from one stage to the next.  
// The authdata might be in the wrong place [127:0] instead of [383:?]
// I may need to add or remove registers to make things fit.  
// [X] Absorb function validated.
// [ ] Encrypt function NOT validated. 
// [ ] squeeze function NOT validated.
// [X] Cyclist initialization validated.



				module xoodyaktop(
					input logic 						eph1,
					input logic 						reset,
					input logic							start,
					
					input logic [191:0] 		textin,  //Either plain text or cipher text depending on opmode
					input logic [127:0] 		nonce,
					input logic [127:0] 	  assodata,
					input logic [127:0] 	  key,
					input logic         		opmode, //0 for encryption, 1 for decryption.  

					output logic [127:0]    authdata,
					output logic [191:0]    textout,
					output logic            encdone  //enc and dec appear to be the same thing here.  

				);

				/* The Keyed mode encryption is defined in section 1.2.2 of "Xoodyak, a lightweight
					 cryptographic scheme."  Specifically, the following steps must be accomplished in sequence4
					 for a text of 192' or less.  
					 Cyclist(Key, *null*, *null*)
					 Absorb(nonce)
					 Absorb(Associated Data)
					 Crypt(textin)  //Note: the encrypt and decrypt functions are the same
					 Squeeze(state) //The squeeze function generates a 128' authentication tag
					 
					 All function calls require a permute() function. */  
	
				logic [383:0] state_initial, state_nonce, state_asso_in, state_asso ;
				logic    nonce_done, auth_start;

				assign state_initial = {key,8'h0, 8'h01, 232'h0, 8'h2}; // So the arguments are {key, mod256(id) which is zero, 8'h01, a bunch of zeros, end with 8'h2.  
				//When using the gimmick short message version: assign state_initial = {key,nonce,8'h10,8'h01, 232'h0, 8'h2}; so this enc8() thing just counts the amount 
				//of bytes that are in the number.  With the gimmick the amount of AD is always 128' and there fore the third argument is always 8'h10.  
				
				absorb absorbnonce(

					.eph1   			(eph1),
					.reset  			(reset),
					.start  			(start),
				
					.state_in 		(state_initial),
					.extra_data 	(nonce),                 //can be either associated data or the nonce. 

					.state_out 		(state_nonce),
					.absorb_done 	(nonce_done)

				);
				
				rregs #(384) absnonc ( state_asso_in, state_nonce, eph1);

				absorb absorbauthdata(
					.eph1   			(eph1),
					.reset  			(reset),
					.start  			(nonce_done),
				
					.state_in 		(state_asso_in),
					.extra_data 	(assodata),                 //can be either associated data or the nonce. 

					.state_out 		(state_asso),
					.absorb_done 	(asso_done)

				);
					
					logic [383:0] state_enc_in;
				rregs #(384) endabs ( state_enc_in, state_asso, eph1);

				crypt encrypt(
					.eph1 				(eph1),
					.reset 				(reset),
					.start 				(asso_done),
					
					.state 				(state_enc_in),
					.cryptin 		  (textin),
					
					.cryptout 	  (textout), //from the encrypt modules  (output pin to top)
					.authdata   	(authdata),  //from the encrypt modules (output pin to top)
					.encdone    	(encdone)
				); 
				
				logic [191:0] dectestvec;
				logic [127:0] authdata_dec;
	      logic encdone_dec;
				
				crypt decryptinst(
				
					.eph1 				(eph1),
					.reset 				(reset),
					.start 				(asso_done),
					
					.state 				(state_enc_in),
					.cryptin 		  (textout),
					
					.cryptout 	  (dectestvec), //from the encrypt modules  (output pin to top)
					.authdata   	(authdata_dec),  //from the encrypt modules (output pin to top)
					.encdone    	(encdone_dec)
				);
				
				

				endmodule: xoodyaktop


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

				module crypt(
				
						input logic          eph1,
						input logic          reset,
						input  logic         start,
						
						input logic [383:0] state,
						input logic [191:0] cryptin,
						
						output logic [191:0] cryptout,
						output logic [127:0] authdata,
						output logic         encdone

				);
				
				/* Encrypt() and Decrypt() are defined in Algorithm 2.
				Both call the crypt() function in Algorithm 3
				and take the input text as an argument. */
				
				
				logic [383:0] state_enc,enc_permd;
				logic encpermflag;

				assign state_enc = {state[383:8],~state[7],state[6:0]}; //XORS domain value 0x80 with the state upon start of encrytion. 

					permute encperm (  //May only need one set of permute hardware.  It may operate  asynchronously from the clock.  
							.eph1           (eph1),
							.reset          (reset),
							.start          (start),
							.state_in       (state_enc),
							.state_out      (enc_permd),
							.xood_done      (encpermflag)
					);

				//XORS up to 192' of message with the state.  
				//assumption: xor'ing with the 192 MSB of the state.

				assign cryptout = cryptin ^ enc_permd[383:192];
				
				
				logic [127:0] final_authtag;
				
				logic [383:0] sqz_in, sqz_ciphertext; 
				assign sqz_ciphertext = {cryptout, enc_permd[191:185], ~enc_permd[184], enc_permd[183:0]};  //a hex 0x01 XOR at the most significant bit after the cryptout.  
				rregs #(384) encsqz ( sqz_in ,sqz_ciphertext, eph1);
				
			squeeze squeezetag(  //consider making this in the top module.  pass to enc and dec as needed based on the situation.  
						.eph1 (eph1),
						.reset (reset),
						.start (encpermflag),
						
						.state   (sqz_in),
						.authtag ( final_authtag),
						.sq_done (encdone)//whenever we're done with both generating the cryptout and the authdata
				
			 );

    assign authdata   = final_authtag;
    
    endmodule: crypt 



    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



			module absorb (
    
					input logic         	eph1,
					input logic          	reset, 
					input logic         	start,
				
					input logic  [383:0] 	state_in,
					input logic  [127:0] 	extra_data, //can be either associated data or the nonce. 

					output logic [383:0] 	state_out,
					output logic         	absorb_done
			);
        /* The absorb function is the same for both associated data and the nonce.
				   Absorb is defined in Algorithm 2 "Definition of Cyclist"
					 Absorb() takes inputs as the input text (extra_data), 
					 and feeds it into ABSORBANY(extra_data,16 bytes,8'h03) - where Rabsorb is 128' or 16 bytes
					 For this implementation there is only one block in 
					 the ABSORBANY() function and the DOWN() function is always called, as
					 DOWN(extra_data,8'h03)
					 */
				logic [383:0] perm_out;
				logic [127:0] state_temp;
				logic       perm_done;

			permute absorbround(
					.eph1       	(eph1),
					.reset     		(reset),
					.start     		(start),
					.state_in  		(state_in),
					.state_out 		(perm_out),
					.xood_done 		(perm_done)
			);

    
		//For DOWN(extra_data,8'h03)
		assign state_temp = extra_data^perm_out[383:256]; //Absorbs the nonce or AD from bytes 0-15 inclusive
		// perm_out ^ (Xi||8'h01||'00(extended)||Cd)  Cd is 8'h03.  
    assign state_out = {state_temp, perm_out[255:249], ~perm_out[248] ,perm_out[247:2], ~perm_out[1:0]};

    assign absorb_done = perm_done;


    endmodule: absorb
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			module squeeze (
			
				input logic          		eph1,
				input logic          		reset, 
				input logic          		start,

				input logic  [383:0] 		state,
				
				output logic [127:0] 		authtag,
				output logic 						sq_done

			);
			logic [383:0] perm_in, perm_out;
			logic perm_done;

			assign perm_in = {state[383:7], ~state[6], state[5:0]}; //computationally finds: 0x40 ^ state;

				permute sqzrnd(
    
						.eph1       (eph1),
						.reset     (reset),
						.start     (start),
						.state_in  (perm_in),
						.state_out (perm_out),
						.xood_done (perm_done)
    
				);

      assign authtag = perm_out[383:256];//is it 127:0 or 383:255 191
		  assign sq_done = perm_done;
			
			endmodule: squeeze
 
 
     
      module permute( 
      
          input logic          eph1,
          input logic          reset, 
          input logic          start,  //start has to be a pulse.  
          
          input logic  [383:0] state_in,  //Indicies: plane, lane, zed
          
          output logic [383:0] state_out,
          output logic         xood_done 

      );
        
/* Permute requires:                                                                       //These function requirements have not been formalized or created yet.  
A constantly asserted (0 or 1) eph1, reset, start
start must be a pulse input. 
The state_in is read @posedge start and must be valid when that occurs.
                    
              
Permute produces:
A 384' permuted state, which is the function's output.
A xood_done flag, which tells the user that the permute function is complete.  
A running permutation cannot be cancelled and will not accept inputs until it completes.  
        
        
           Each round from 0 to b is identical.  Round 0 is documented thorougly.  Other rounds are not.  
           Refer to round 0's documentation to determine the nature of behavior.  
           
           Variables are appended with _X to refer to their round of use.  Index begins at zero.  For example,
           theta_out_4 refers to the output of the fifth round's θ function.  

           Round zero defines terms with reference to the original Xoodoo documentation on Algorithm 1,
           Page 6 of "Xoodyak, A Lightweight Encryption Scheme."  
           
           Xoodyak's state is concevied as 384' of three 128' overlaid planes, where the index of the state,
           i = z + 32*(x+4*y), where x, y, and z are dimensions.  In this implementation, the state is indexed as
           [y][x][z], or [plane][lane][depth].  
           
           All shifts are barrel shifts; zeros are never concatenated as shift in bits.  

           ***WARNING! Table 2 of the the specification requires that the round constant's least significant bit is at z = 0,
           but software test benching has reversed what order these values are applied.  For consistency purposes I have 
           kept them reversed to match the software, but this is not algorithmically correct per the specification.
           
           ***Caution! As of 18MAY2021 input and output bits are reconcatenated to match software benchmarking tools which
           operate in little endian.  This reconcatenation is not included in the specification and should not be included
           in any synthesization of this code.  
           
           Symbolic variables:
           Ay, a 128' plane with index y from [2:0].
           P,  defined as A0 ^ A1 ^ A2
           E,  defined as P<<<(1, 5) + P<<<(1, 14).  (x,z) where x is a left shift by 32', and z is a left shift by 1 bit.  
           Ci, a round constant depending on the round.  Beginning with round 0's constant and ending with round b's constant,
               they are : { 32'h58, 32'h38, 32'h3c0, 32'hD0, 32'h120, 32'h14, 32'h60, 32'h2c, 32'h380, 32'hF0, 32'h1A0, 32'h12}
           */
        
        
        
        
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////////////////Permute Setup//////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        //Greek syms.  θ ρwest ι Χ ρeast
        //The CIBOX constants, retained for reference, are: '{ 32'h58, 32'h38, 32'h3c0, 32'hD0, 32'h120, 32'h14, 32'h60, 32'h2c, 32'h380, 32'hF0, 32'h1A0, 32'h12}; 
rregs #(1) xoodne (xood_done,reset?1'h0:(~xood_done&start),eph1); //This is fake.  I am assuming the entire thing will only take one clock which won't be true.  
      
        logic [383:0]  bits_le;
        assign bits_le = {// So not only is each block of 32' reversed in a 128' double double word, but each 
                          //128' double double word position is reversed in the total state.  Fuck that are you kidding me?  
                          state_in[103:96] ,state_in[111:104],state_in[119:112],state_in[127:120],
                          state_in[71:64]  ,state_in[79:72]  ,state_in[87:80]  ,state_in[95:88],
                          state_in[39:32]  ,state_in[47:40]  ,state_in[55:48]  ,state_in[63:56],
                          state_in[7:0]    ,state_in[15:8]   ,state_in[23:16]  ,state_in[31:24],
                          
                          state_in[231:224],state_in[239:232],state_in[247:240],state_in[255:248],
                          state_in[199:192],state_in[207:200],state_in[215:208],state_in[223:216],
                          state_in[167:160],state_in[175:168],state_in[183:176],state_in[191:184],
                          state_in[135:128],state_in[143:136],state_in[151:144],state_in[159:152],
                          
                          state_in[359:352],state_in[367:360],state_in[375:368],state_in[383:376],
                          state_in[327:320],state_in[335:328],state_in[343:336],state_in[351:344],
                          state_in[295:288],state_in[303:296],state_in[311:304],state_in[319:312],
                          state_in[263:256],state_in[271:264],state_in[279:272],state_in[287:280]
                          };
        
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round zero///////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        //θ 
        
        logic [3:0][31:0] p_0, e_0; //Indicies: lane, zed.
        logic [2:0][3:0][31:0] perm_input_0;

        assign perm_input_0 = bits_le;
        
        // P <- A0 + A1 + A2
        assign p_0 =  perm_input_0[0]^perm_input_0[1]^perm_input_0[2];  //Will need to make a better version later.  

        // P<<<(1, 5)
        logic [3:0][31:0] p_x1_z5_0, p_x1_z14_0;
        assign p_x1_z5_0[3] = {p_0[0][26:0], p_0[0][31:27]}; 
        assign p_x1_z5_0[2] = {p_0[3][26:0], p_0[3][31:27]}; 
        assign p_x1_z5_0[1] = {p_0[2][26:0], p_0[2][31:27]}; 
        assign p_x1_z5_0[0] = {p_0[1][26:0], p_0[1][31:27]};

        // P<<<(1, 14)
        assign p_x1_z14_0[3] ={p_0[0][17:0], p_0[0][31:18]};
        assign p_x1_z14_0[2] ={p_0[3][17:0], p_0[3][31:18]}; 
        assign p_x1_z14_0[1] ={p_0[2][17:0], p_0[2][31:18]}; 
        assign p_x1_z14_0[0] ={p_0[1][17:0], p_0[1][31:18]};  

        // E <- P<<<(1, 5) ^  P<<<(1, 14)
        assign e_0 = p_x1_z5_0^p_x1_z14_0;

        
        // Ay <- Ay ^ E, for y={0,1,2}
        logic [2:0][3:0][31:0] theta_out_0;
        
        assign theta_out_0[2] = perm_input_0[2]^e_0;
        assign theta_out_0[1] = perm_input_0[1]^e_0;
        assign theta_out_0[0] = perm_input_0[0]^e_0;

        //End θ


        //ρwest
                
        logic [2:0][3:0][31:0] rho_west_0;

        // A2 <- A2<<<(0,11)
        // Shifts the A2 plane 11 bits in the +z direction.  
        assign rho_west_0[2][3] = {theta_out_0[2][3][20:0] , theta_out_0[2][3][31:21]};
        assign rho_west_0[2][2] = {theta_out_0[2][2][20:0] , theta_out_0[2][2][31:21]};
        assign rho_west_0[2][1] = {theta_out_0[2][1][20:0] , theta_out_0[2][1][31:21]};
        assign rho_west_0[2][0] = {theta_out_0[2][0][20:0] , theta_out_0[2][0][31:21]};

        // A1 <- A1<<<(1,0)
        assign rho_west_0[1][3] = theta_out_0[1][0];
        assign rho_west_0[1][2] = theta_out_0[1][3];
        assign rho_west_0[1][1] = theta_out_0[1][2];
        assign rho_west_0[1][0] = theta_out_0[1][1];
        

        // ι, which is included as part of ρwest
        // A0 <- A0^Ci 
     /***WARNING! Table 2 of the the specification requires that the round constant's least significant bit is at z = 0,
         but software test benching has reversed what order these values are applied.  For consistency purposes I have 
         kept them reversed to match the software, but this is not algorithmically correct per the specification.*** */
assign rho_west_0[0][3] = theta_out_0[0][3] ^ {32'h58}; 
        assign rho_west_0[0][2] = theta_out_0[0][2]; 
        assign rho_west_0[0][1] = theta_out_0[0][1]; 
assign rho_west_0[0][0] = theta_out_0[0][0];  //The round constant, 32'h58, should be applied HERE.

        //END ρwest
          

        //Χ  
        logic [2:0][3:0][31:0] chi_out_0;
        
        //Logically computes the following steps:
        // B0 <- ~A1^A2
        // B1 <- ~A2^A0
        // B2 <- ~A0^A1
        // Ay <- Ay^By for y{0,1,2{
        assign chi_out_0[2] = rho_west_0[2]^(rho_west_0[1]&~rho_west_0[0]);
        assign chi_out_0[1] = rho_west_0[1]^(rho_west_0[0]&~rho_west_0[2]);
        assign chi_out_0[0] = rho_west_0[0]^(rho_west_0[2]&~rho_west_0[1]);
        
        //END X
        
        
        //ρeast
        
        logic [2:0][3:0][31:0] rho_east_0;
        
        //A2 <- A2<<<(2,8)
        assign rho_east_0[2][3] = {chi_out_0[2][1][23:0], chi_out_0[2][1][31:24]};
        assign rho_east_0[2][2] = {chi_out_0[2][0][23:0], chi_out_0[2][0][31:24]};
        assign rho_east_0[2][1] = {chi_out_0[2][3][23:0], chi_out_0[2][3][31:24]};
        assign rho_east_0[2][0] = {chi_out_0[2][2][23:0], chi_out_0[2][2][31:24]};

        //A1 <- A1<<<(0,1)
        assign rho_east_0[1][3] = {chi_out_0[1][3][30:0], chi_out_0[1][3][31]};  
        assign rho_east_0[1][2] = {chi_out_0[1][2][30:0], chi_out_0[1][2][31]};
        assign rho_east_0[1][1] = {chi_out_0[1][1][30:0], chi_out_0[1][1][31]};
        assign rho_east_0[1][0] = {chi_out_0[1][0][30:0], chi_out_0[1][0][31]};
       
       //A0 is not modified. 
       assign rho_east_0[0] = chi_out_0[0];

       //end ρeast
        
        //ρeast is the final step in the permutation.  The output of round n is fed directly into 
        //round n+1.  
        
        logic [383:0] round_out_0;
        assign round_out_0 = rho_east_0;


        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round one////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////

        logic [3:0][31:0] p_1, e_1; 
        logic [2:0][3:0][31:0] perm_input_1;

        assign perm_input_1 = round_out_0;
        assign p_1 =  perm_input_1[0]^perm_input_1[1]^perm_input_1[2];  

  
        logic [3:0][31:0] p_x1_z5_1, p_x1_z14_1;
        assign p_x1_z5_1[3] = {p_1[0][26:0], p_1[0][31:27]}; 
        assign p_x1_z5_1[2] = {p_1[3][26:0], p_1[3][31:27]}; 
        assign p_x1_z5_1[1] = {p_1[2][26:0], p_1[2][31:27]}; 
        assign p_x1_z5_1[0] = {p_1[1][26:0], p_1[1][31:27]};

        assign p_x1_z14_1[3] ={p_1[0][17:0], p_1[0][31:18]};
        assign p_x1_z14_1[2] ={p_1[3][17:0], p_1[3][31:18]}; 
        assign p_x1_z14_1[1] ={p_1[2][17:0], p_1[2][31:18]}; 
        assign p_x1_z14_1[0] ={p_1[1][17:0], p_1[1][31:18]};  

        assign e_1 = p_x1_z5_1^p_x1_z14_1;

        logic [2:0][3:0][31:0] theta_out_1;

        assign theta_out_1[2] = perm_input_1[2]^e_1;
        assign theta_out_1[1] = perm_input_1[1]^e_1;
        assign theta_out_1[0] = perm_input_1[0]^e_1;
        
        logic [2:0][3:0][31:0] rho_west_1;

        assign rho_west_1[2][3] = {theta_out_1[2][3][20:0] , theta_out_1[2][3][31:21]};
        assign rho_west_1[2][2] = {theta_out_1[2][2][20:0] , theta_out_1[2][2][31:21]};
        assign rho_west_1[2][1] = {theta_out_1[2][1][20:0] , theta_out_1[2][1][31:21]};
        assign rho_west_1[2][0] = {theta_out_1[2][0][20:0] , theta_out_1[2][0][31:21]};

        assign rho_west_1[1][3] = theta_out_1[1][0];
        assign rho_west_1[1][2] = theta_out_1[1][3];
        assign rho_west_1[1][1] = theta_out_1[1][2];
        assign rho_west_1[1][0] = theta_out_1[1][1];


assign rho_west_1[0][3] = theta_out_1[0][3] ^ {32'h38}; 
        assign rho_west_1[0][2] = theta_out_1[0][2]; 
        assign rho_west_1[0][1] = theta_out_1[0][1]; 
assign rho_west_1[0][0] = theta_out_1[0][0]; 
  
          

        logic [2:0][3:0][31:0] chi_out_1;

        assign chi_out_1[2] = rho_west_1[2]^(rho_west_1[1]&~rho_west_1[0]);
        assign chi_out_1[1] = rho_west_1[1]^(rho_west_1[0]&~rho_west_1[2]);
        assign chi_out_1[0] = rho_west_1[0]^(rho_west_1[2]&~rho_west_1[1]);
        
        //rho_east_1
        logic [2:0][3:0][31:0] rho_east_1;

      
        assign rho_east_1[2][3] = {chi_out_1[2][1][23:0], chi_out_1[2][1][31:24]};
        assign rho_east_1[2][2] = {chi_out_1[2][0][23:0], chi_out_1[2][0][31:24]};
        assign rho_east_1[2][1] = {chi_out_1[2][3][23:0], chi_out_1[2][3][31:24]};
        assign rho_east_1[2][0] = {chi_out_1[2][2][23:0], chi_out_1[2][2][31:24]};

        assign rho_east_1[1][3] = {chi_out_1[1][3][30:0], chi_out_1[1][3][31]};  
        assign rho_east_1[1][2] = {chi_out_1[1][2][30:0], chi_out_1[1][2][31]};
        assign rho_east_1[1][1] = {chi_out_1[1][1][30:0], chi_out_1[1][1][31]};
        assign rho_east_1[1][0] = {chi_out_1[1][0][30:0], chi_out_1[1][0][31]};
       
       assign rho_east_1[0] = chi_out_1[0];

        logic [383:0] round_out_1;
        
        assign round_out_1 = rho_east_1;

        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round two////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////

        
        logic [3:0][31:0] p_2, e_2; 
        logic [2:0][3:0][31:0] perm_input_2;

        assign perm_input_2 = round_out_1;
        assign p_2 =  perm_input_2[0]^perm_input_2[1]^perm_input_2[2];  //Will need to make a better version later.  

        //write as function perhaps191
        logic [3:0][31:0] p_x1_z5_2, p_x1_z14_2;
        assign p_x1_z5_2[3] = {p_2[0][26:0], p_2[0][31:27]}; 
        assign p_x1_z5_2[2] = {p_2[3][26:0], p_2[3][31:27]}; 
        assign p_x1_z5_2[1] = {p_2[2][26:0], p_2[2][31:27]}; 
        assign p_x1_z5_2[0] = {p_2[1][26:0], p_2[1][31:27]};

        assign p_x1_z14_2[3] ={p_2[0][17:0], p_2[0][31:18]};
        assign p_x1_z14_2[2] ={p_2[3][17:0], p_2[3][31:18]}; 
        assign p_x1_z14_2[1] ={p_2[2][17:0], p_2[2][31:18]}; 
        assign p_x1_z14_2[0] ={p_2[1][17:0], p_2[1][31:18]};  

        assign e_2 = p_x1_z5_2^p_x1_z14_2;

        logic [2:0][3:0][31:0] theta_out_2;

        assign theta_out_2[2] = perm_input_2[2]^e_2;
        assign theta_out_2[1] = perm_input_2[1]^e_2;
        assign theta_out_2[0] = perm_input_2[0]^e_2;
        
        logic [2:0][3:0][31:0] rho_west_2;

        assign rho_west_2[2][3] = {theta_out_2[2][3][20:0] , theta_out_2[2][3][31:21]};
        assign rho_west_2[2][2] = {theta_out_2[2][2][20:0] , theta_out_2[2][2][31:21]};
        assign rho_west_2[2][1] = {theta_out_2[2][1][20:0] , theta_out_2[2][1][31:21]};
        assign rho_west_2[2][0] = {theta_out_2[2][0][20:0] , theta_out_2[2][0][31:21]};

        assign rho_west_2[1][3] = theta_out_2[1][0];
        assign rho_west_2[1][2] = theta_out_2[1][3];
        assign rho_west_2[1][1] = theta_out_2[1][2];
        assign rho_west_2[1][0] = theta_out_2[1][1];


assign rho_west_2[0][3] = theta_out_2[0][3] ^ {32'h3c0}; 
          assign rho_west_2[0][2] = theta_out_2[0][2]; 
          assign rho_west_2[0][1] = theta_out_2[0][1]; 
assign rho_west_2[0][0] = theta_out_2[0][0];

        logic [2:0][3:0][31:0] chi_out_2;

        assign chi_out_2[2] = rho_west_2[2]^(rho_west_2[1]&~rho_west_2[0]);
        assign chi_out_2[1] = rho_west_2[1]^(rho_west_2[0]&~rho_west_2[2]);
        assign chi_out_2[0] = rho_west_2[0]^(rho_west_2[2]&~rho_west_2[1]);
        
        //rho_east_2
        logic [2:0][3:0][31:0] rho_east_2;

      
        assign rho_east_2[2][3] = {chi_out_2[2][1][23:0], chi_out_2[2][1][31:24]};
        assign rho_east_2[2][2] = {chi_out_2[2][0][23:0], chi_out_2[2][0][31:24]};
        assign rho_east_2[2][1] = {chi_out_2[2][3][23:0], chi_out_2[2][3][31:24]};
        assign rho_east_2[2][0] = {chi_out_2[2][2][23:0], chi_out_2[2][2][31:24]};

        assign rho_east_2[1][3] = {chi_out_2[1][3][30:0], chi_out_2[1][3][31]};  
        assign rho_east_2[1][2] = {chi_out_2[1][2][30:0], chi_out_2[1][2][31]};
        assign rho_east_2[1][1] = {chi_out_2[1][1][30:0], chi_out_2[1][1][31]};
        assign rho_east_2[1][0] = {chi_out_2[1][0][30:0], chi_out_2[1][0][31]};
       
       assign rho_east_2[0] = chi_out_2[0];

        logic [383:0] round_out_2;
        
        assign round_out_2 = rho_east_2;

        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round three//////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////

  
        logic [3:0][31:0] p_3, e_3; 
        logic [2:0][3:0][31:0] perm_input_3;

        assign perm_input_3 = round_out_2;
        assign p_3 =  perm_input_3[0]^perm_input_3[1]^perm_input_3[2];  

        
        logic [3:0][31:0] p_x1_z5_3, p_x1_z14_3;
        assign p_x1_z5_3[3] = {p_3[0][26:0], p_3[0][31:27]}; 
        assign p_x1_z5_3[2] = {p_3[3][26:0], p_3[3][31:27]}; 
        assign p_x1_z5_3[1] = {p_3[2][26:0], p_3[2][31:27]}; 
        assign p_x1_z5_3[0] = {p_3[1][26:0], p_3[1][31:27]};

        assign p_x1_z14_3[3] ={p_3[0][17:0], p_3[0][31:18]};
        assign p_x1_z14_3[2] ={p_3[3][17:0], p_3[3][31:18]}; 
        assign p_x1_z14_3[1] ={p_3[2][17:0], p_3[2][31:18]}; 
        assign p_x1_z14_3[0] ={p_3[1][17:0], p_3[1][31:18]};  

        assign e_3 = p_x1_z5_3^p_x1_z14_3;

        logic [2:0][3:0][31:0] theta_out_3;

        assign theta_out_3[2] = perm_input_3[2]^e_3;
        assign theta_out_3[1] = perm_input_3[1]^e_3;
        assign theta_out_3[0] = perm_input_3[0]^e_3;

        logic [2:0][3:0][31:0] rho_west_3;

     
        assign rho_west_3[2][3] = {theta_out_3[2][3][20:0] , theta_out_3[2][3][31:21]};
        assign rho_west_3[2][2] = {theta_out_3[2][2][20:0] , theta_out_3[2][2][31:21]};
        assign rho_west_3[2][1] = {theta_out_3[2][1][20:0] , theta_out_3[2][1][31:21]};
        assign rho_west_3[2][0] = {theta_out_3[2][0][20:0] , theta_out_3[2][0][31:21]};

        assign rho_west_3[1][3] = theta_out_3[1][0];
        assign rho_west_3[1][2] = theta_out_3[1][3];
        assign rho_west_3[1][1] = theta_out_3[1][2];
        assign rho_west_3[1][0] = theta_out_3[1][1];


assign rho_west_3[0][3] = theta_out_3[0][3] ^ {32'hd0}; 
          assign rho_west_3[0][2] = theta_out_3[0][2]; 
          assign rho_west_3[0][1] = theta_out_3[0][1]; 
assign rho_west_3[0][0] = theta_out_3[0][0];
          

        logic [2:0][3:0][31:0] chi_out_3;

        assign chi_out_3[2] = rho_west_3[2]^(rho_west_3[1]&~rho_west_3[0]);
        assign chi_out_3[1] = rho_west_3[1]^(rho_west_3[0]&~rho_west_3[2]);
        assign chi_out_3[0] = rho_west_3[0]^(rho_west_3[2]&~rho_west_3[1]);
        
        //rho_east_3
        logic [2:0][3:0][31:0] rho_east_3;

        assign rho_east_3[2][3] = {chi_out_3[2][1][23:0], chi_out_3[2][1][31:24]};
        assign rho_east_3[2][2] = {chi_out_3[2][0][23:0], chi_out_3[2][0][31:24]};
        assign rho_east_3[2][1] = {chi_out_3[2][3][23:0], chi_out_3[2][3][31:24]};
        assign rho_east_3[2][0] = {chi_out_3[2][2][23:0], chi_out_3[2][2][31:24]};

        assign rho_east_3[1][3] = {chi_out_3[1][3][30:0], chi_out_3[1][3][31]};  
        assign rho_east_3[1][2] = {chi_out_3[1][2][30:0], chi_out_3[1][2][31]};
        assign rho_east_3[1][1] = {chi_out_3[1][1][30:0], chi_out_3[1][1][31]};
        assign rho_east_3[1][0] = {chi_out_3[1][0][30:0], chi_out_3[1][0][31]};
       
       assign rho_east_3[0] = chi_out_3[0];

        logic [383:0] round_out_3;
        
        assign round_out_3 = rho_east_3;

        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round four///////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////


        logic [3:0][31:0] p_4, e_4; 
        logic [2:0][3:0][31:0] perm_input_4;

        assign perm_input_4 = round_out_3;
        assign p_4 =  perm_input_4[0]^perm_input_4[1]^perm_input_4[2];  

        
        logic [3:0][31:0] p_x1_z5_4, p_x1_z14_4;
        assign p_x1_z5_4[3] = {p_4[0][26:0], p_4[0][31:27]}; 
        assign p_x1_z5_4[2] = {p_4[3][26:0], p_4[3][31:27]}; 
        assign p_x1_z5_4[1] = {p_4[2][26:0], p_4[2][31:27]}; 
        assign p_x1_z5_4[0] = {p_4[1][26:0], p_4[1][31:27]};

        assign p_x1_z14_4[3] ={p_4[0][17:0], p_4[0][31:18]};
        assign p_x1_z14_4[2] ={p_4[3][17:0], p_4[3][31:18]}; 
        assign p_x1_z14_4[1] ={p_4[2][17:0], p_4[2][31:18]}; 
        assign p_x1_z14_4[0] ={p_4[1][17:0], p_4[1][31:18]};  

        assign e_4 = p_x1_z5_4^p_x1_z14_4;

        logic [2:0][3:0][31:0] theta_out_4;

        assign theta_out_4[2] = perm_input_4[2]^e_4;
        assign theta_out_4[1] = perm_input_4[1]^e_4;
        assign theta_out_4[0] = perm_input_4[0]^e_4;

        logic [2:0][3:0][31:0] rho_west_4;

     
        assign rho_west_4[2][3] = {theta_out_4[2][3][20:0] , theta_out_4[2][3][31:21]};
        assign rho_west_4[2][2] = {theta_out_4[2][2][20:0] , theta_out_4[2][2][31:21]};
        assign rho_west_4[2][1] = {theta_out_4[2][1][20:0] , theta_out_4[2][1][31:21]};
        assign rho_west_4[2][0] = {theta_out_4[2][0][20:0] , theta_out_4[2][0][31:21]};

        assign rho_west_4[1][3] = theta_out_4[1][0];
        assign rho_west_4[1][2] = theta_out_4[1][3];
        assign rho_west_4[1][1] = theta_out_4[1][2];
        assign rho_west_4[1][0] = theta_out_4[1][1];

assign rho_west_4[0][3] = theta_out_4[0][3] ^ {32'h120}; 
          assign rho_west_4[0][2] = theta_out_4[0][2]; 
          assign rho_west_4[0][1] = theta_out_4[0][1]; 
assign rho_west_4[0][0] = theta_out_4[0][0];  
          

        logic [2:0][3:0][31:0] chi_out_4;

        assign chi_out_4[2] = rho_west_4[2]^(rho_west_4[1]&~rho_west_4[0]);
        assign chi_out_4[1] = rho_west_4[1]^(rho_west_4[0]&~rho_west_4[2]);
        assign chi_out_4[0] = rho_west_4[0]^(rho_west_4[2]&~rho_west_4[1]);
        
        logic [2:0][3:0][31:0] rho_east_4;
      
        assign rho_east_4[2][3] = {chi_out_4[2][1][23:0], chi_out_4[2][1][31:24]};
        assign rho_east_4[2][2] = {chi_out_4[2][0][23:0], chi_out_4[2][0][31:24]};
        assign rho_east_4[2][1] = {chi_out_4[2][3][23:0], chi_out_4[2][3][31:24]};
        assign rho_east_4[2][0] = {chi_out_4[2][2][23:0], chi_out_4[2][2][31:24]};

        assign rho_east_4[1][3] = {chi_out_4[1][3][30:0], chi_out_4[1][3][31]};  
        assign rho_east_4[1][2] = {chi_out_4[1][2][30:0], chi_out_4[1][2][31]};
        assign rho_east_4[1][1] = {chi_out_4[1][1][30:0], chi_out_4[1][1][31]};
        assign rho_east_4[1][0] = {chi_out_4[1][0][30:0], chi_out_4[1][0][31]};
       
       assign rho_east_4[0] = chi_out_4[0];

        logic [383:0] round_out_4;
        
        assign round_out_4 = rho_east_4;

        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round five///////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////


        logic [3:0][31:0] p_5, e_5; 
        logic [2:0][3:0][31:0] perm_input_5;

        assign perm_input_5 = round_out_4;
        assign p_5 =  perm_input_5[0]^perm_input_5[1]^perm_input_5[2];  

        
        logic [3:0][31:0] p_x1_z5_5, p_x1_z14_5;
        assign p_x1_z5_5[3] = {p_5[0][26:0], p_5[0][31:27]}; 
        assign p_x1_z5_5[2] = {p_5[3][26:0], p_5[3][31:27]}; 
        assign p_x1_z5_5[1] = {p_5[2][26:0], p_5[2][31:27]}; 
        assign p_x1_z5_5[0] = {p_5[1][26:0], p_5[1][31:27]};

        assign p_x1_z14_5[3] ={p_5[0][17:0], p_5[0][31:18]};
        assign p_x1_z14_5[2] ={p_5[3][17:0], p_5[3][31:18]}; 
        assign p_x1_z14_5[1] ={p_5[2][17:0], p_5[2][31:18]}; 
        assign p_x1_z14_5[0] ={p_5[1][17:0], p_5[1][31:18]};  

        assign e_5 = p_x1_z5_5^p_x1_z14_5;

        logic [2:0][3:0][31:0] theta_out_5;

        assign theta_out_5[2] = perm_input_5[2]^e_5;
        assign theta_out_5[1] = perm_input_5[1]^e_5;
        assign theta_out_5[0] = perm_input_5[0]^e_5;

        logic [2:0][3:0][31:0] rho_west_5;
     
        assign rho_west_5[2][3] = {theta_out_5[2][3][20:0] , theta_out_5[2][3][31:21]};
        assign rho_west_5[2][2] = {theta_out_5[2][2][20:0] , theta_out_5[2][2][31:21]};
        assign rho_west_5[2][1] = {theta_out_5[2][1][20:0] , theta_out_5[2][1][31:21]};
        assign rho_west_5[2][0] = {theta_out_5[2][0][20:0] , theta_out_5[2][0][31:21]};

        assign rho_west_5[1][3] = theta_out_5[1][0];
        assign rho_west_5[1][2] = theta_out_5[1][3];
        assign rho_west_5[1][1] = theta_out_5[1][2];
        assign rho_west_5[1][0] = theta_out_5[1][1];

assign rho_west_5[0][3] = theta_out_5[0][3] ^ {32'h14}; 
        assign rho_west_5[0][2] = theta_out_5[0][2]; 
        assign rho_west_5[0][1] = theta_out_5[0][1]; 
assign rho_west_5[0][0] = theta_out_5[0][0];
          

        logic [2:0][3:0][31:0] chi_out_5;

        assign chi_out_5[2] = rho_west_5[2]^(rho_west_5[1]&~rho_west_5[0]);
        assign chi_out_5[1] = rho_west_5[1]^(rho_west_5[0]&~rho_west_5[2]);
        assign chi_out_5[0] = rho_west_5[0]^(rho_west_5[2]&~rho_west_5[1]);
        
        logic [2:0][3:0][31:0] rho_east_5;
      
        assign rho_east_5[2][3] = {chi_out_5[2][1][23:0], chi_out_5[2][1][31:24]};
        assign rho_east_5[2][2] = {chi_out_5[2][0][23:0], chi_out_5[2][0][31:24]};
        assign rho_east_5[2][1] = {chi_out_5[2][3][23:0], chi_out_5[2][3][31:24]};
        assign rho_east_5[2][0] = {chi_out_5[2][2][23:0], chi_out_5[2][2][31:24]};

        assign rho_east_5[1][3] = {chi_out_5[1][3][30:0], chi_out_5[1][3][31]};  
        assign rho_east_5[1][2] = {chi_out_5[1][2][30:0], chi_out_5[1][2][31]};
        assign rho_east_5[1][1] = {chi_out_5[1][1][30:0], chi_out_5[1][1][31]};
        assign rho_east_5[1][0] = {chi_out_5[1][0][30:0], chi_out_5[1][0][31]};
       
       assign rho_east_5[0] = chi_out_5[0];

        logic [383:0] round_out_5;
        
        assign round_out_5 = rho_east_5;
        
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round six////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////

        logic [3:0][31:0] p_6, e_6; 
        logic [2:0][3:0][31:0] perm_input_6;

        assign perm_input_6 = round_out_5;
        assign p_6 =  perm_input_6[0]^perm_input_6[1]^perm_input_6[2];  

        
        logic [3:0][31:0] p_x1_z5_6, p_x1_z14_6;
        assign p_x1_z5_6[3] = {p_6[0][26:0], p_6[0][31:27]}; 
        assign p_x1_z5_6[2] = {p_6[3][26:0], p_6[3][31:27]}; 
        assign p_x1_z5_6[1] = {p_6[2][26:0], p_6[2][31:27]}; 
        assign p_x1_z5_6[0] = {p_6[1][26:0], p_6[1][31:27]};

        assign p_x1_z14_6[3] ={p_6[0][17:0], p_6[0][31:18]};
        assign p_x1_z14_6[2] ={p_6[3][17:0], p_6[3][31:18]}; 
        assign p_x1_z14_6[1] ={p_6[2][17:0], p_6[2][31:18]}; 
        assign p_x1_z14_6[0] ={p_6[1][17:0], p_6[1][31:18]};  

        assign e_6 = p_x1_z5_6^p_x1_z14_6;

        logic [2:0][3:0][31:0] theta_out_6;

        assign theta_out_6[2] = perm_input_6[2]^e_6;
        assign theta_out_6[1] = perm_input_6[1]^e_6;
        assign theta_out_6[0] = perm_input_6[0]^e_6;

        logic [2:0][3:0][31:0] rho_west_6;

        assign rho_west_6[2][3] = {theta_out_6[2][3][20:0] , theta_out_6[2][3][31:21]};
        assign rho_west_6[2][2] = {theta_out_6[2][2][20:0] , theta_out_6[2][2][31:21]};
        assign rho_west_6[2][1] = {theta_out_6[2][1][20:0] , theta_out_6[2][1][31:21]};
        assign rho_west_6[2][0] = {theta_out_6[2][0][20:0] , theta_out_6[2][0][31:21]};

        assign rho_west_6[1][3] = theta_out_6[1][0];
        assign rho_west_6[1][2] = theta_out_6[1][3];
        assign rho_west_6[1][1] = theta_out_6[1][2];
        assign rho_west_6[1][0] = theta_out_6[1][1];

assign rho_west_6[0][3] = theta_out_6[0][3] ^ {32'h60}; 
        assign rho_west_6[0][2] = theta_out_6[0][2]; 
        assign rho_west_6[0][1] = theta_out_6[0][1]; 
assign rho_west_6[0][0] = theta_out_6[0][0];// ^ CIBOX[rnd_cnt]; Should be this one but it's not.  
          

        logic [2:0][3:0][31:0] chi_out_6;

        assign chi_out_6[2] = rho_west_6[2]^(rho_west_6[1]&~rho_west_6[0]);
        assign chi_out_6[1] = rho_west_6[1]^(rho_west_6[0]&~rho_west_6[2]);
        assign chi_out_6[0] = rho_west_6[0]^(rho_west_6[2]&~rho_west_6[1]);
        
        
        logic [2:0][3:0][31:0] rho_east_6;
        
        assign rho_east_6[2][3] = {chi_out_6[2][1][23:0], chi_out_6[2][1][31:24]};
        assign rho_east_6[2][2] = {chi_out_6[2][0][23:0], chi_out_6[2][0][31:24]};
        assign rho_east_6[2][1] = {chi_out_6[2][3][23:0], chi_out_6[2][3][31:24]};
        assign rho_east_6[2][0] = {chi_out_6[2][2][23:0], chi_out_6[2][2][31:24]};

        assign rho_east_6[1][3] = {chi_out_6[1][3][30:0], chi_out_6[1][3][31]};  
        assign rho_east_6[1][2] = {chi_out_6[1][2][30:0], chi_out_6[1][2][31]};
        assign rho_east_6[1][1] = {chi_out_6[1][1][30:0], chi_out_6[1][1][31]};
        assign rho_east_6[1][0] = {chi_out_6[1][0][30:0], chi_out_6[1][0][31]};
       
       assign rho_east_6[0] = chi_out_6[0];

        logic [383:0] round_out_6;
        
        assign round_out_6 = rho_east_6;


        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round seven//////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////

        logic [3:0][31:0] p_7, e_7; 
        logic [2:0][3:0][31:0] perm_input_7;

        assign perm_input_7 = round_out_6;
        assign p_7 =  perm_input_7[0]^perm_input_7[1]^perm_input_7[2];  

        
        logic [3:0][31:0] p_x1_z5_7, p_x1_z14_7;
        assign p_x1_z5_7[3] = {p_7[0][26:0], p_7[0][31:27]}; 
        assign p_x1_z5_7[2] = {p_7[3][26:0], p_7[3][31:27]}; 
        assign p_x1_z5_7[1] = {p_7[2][26:0], p_7[2][31:27]}; 
        assign p_x1_z5_7[0] = {p_7[1][26:0], p_7[1][31:27]};

        assign p_x1_z14_7[3] ={p_7[0][17:0], p_7[0][31:18]};
        assign p_x1_z14_7[2] ={p_7[3][17:0], p_7[3][31:18]}; 
        assign p_x1_z14_7[1] ={p_7[2][17:0], p_7[2][31:18]}; 
        assign p_x1_z14_7[0] ={p_7[1][17:0], p_7[1][31:18]};  

        assign e_7 = p_x1_z5_7^p_x1_z14_7;

        logic [2:0][3:0][31:0] theta_out_7;

        assign theta_out_7[2] = perm_input_7[2]^e_7;
        assign theta_out_7[1] = perm_input_7[1]^e_7;
        assign theta_out_7[0] = perm_input_7[0]^e_7;
        
        logic [2:0][3:0][31:0] rho_west_7;
     
        assign rho_west_7[2][3] = {theta_out_7[2][3][20:0] , theta_out_7[2][3][31:21]};
        assign rho_west_7[2][2] = {theta_out_7[2][2][20:0] , theta_out_7[2][2][31:21]};
        assign rho_west_7[2][1] = {theta_out_7[2][1][20:0] , theta_out_7[2][1][31:21]};
        assign rho_west_7[2][0] = {theta_out_7[2][0][20:0] , theta_out_7[2][0][31:21]};

        assign rho_west_7[1][3] = theta_out_7[1][0];
        assign rho_west_7[1][2] = theta_out_7[1][3];
        assign rho_west_7[1][1] = theta_out_7[1][2];
        assign rho_west_7[1][0] = theta_out_7[1][1];
        
assign rho_west_7[0][3] = theta_out_7[0][3] ^ {32'h2c}; 
        assign rho_west_7[0][2] = theta_out_7[0][2]; 
        assign rho_west_7[0][1] = theta_out_7[0][1]; 
assign rho_west_7[0][0] = theta_out_7[0][0];
          
        logic [2:0][3:0][31:0] chi_out_7;

        assign chi_out_7[2] = rho_west_7[2]^(rho_west_7[1]&~rho_west_7[0]);
        assign chi_out_7[1] = rho_west_7[1]^(rho_west_7[0]&~rho_west_7[2]);
        assign chi_out_7[0] = rho_west_7[0]^(rho_west_7[2]&~rho_west_7[1]);
        
        logic [2:0][3:0][31:0] rho_east_7;
      
        assign rho_east_7[2][3] = {chi_out_7[2][1][23:0], chi_out_7[2][1][31:24]};
        assign rho_east_7[2][2] = {chi_out_7[2][0][23:0], chi_out_7[2][0][31:24]};
        assign rho_east_7[2][1] = {chi_out_7[2][3][23:0], chi_out_7[2][3][31:24]};
        assign rho_east_7[2][0] = {chi_out_7[2][2][23:0], chi_out_7[2][2][31:24]};

        assign rho_east_7[1][3] = {chi_out_7[1][3][30:0], chi_out_7[1][3][31]};  
        assign rho_east_7[1][2] = {chi_out_7[1][2][30:0], chi_out_7[1][2][31]};
        assign rho_east_7[1][1] = {chi_out_7[1][1][30:0], chi_out_7[1][1][31]};
        assign rho_east_7[1][0] = {chi_out_7[1][0][30:0], chi_out_7[1][0][31]};
       
       assign rho_east_7[0] = chi_out_7[0];

        logic [383:0] round_out_7;
        
        assign round_out_7 = rho_east_7;



        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round eight//////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////

        //Theta input
        logic [3:0][31:0] p_8, e_8; 
        logic [2:0][3:0][31:0] perm_input_8;

        assign perm_input_8 = round_out_7;
        assign p_8 =  perm_input_8[0]^perm_input_8[1]^perm_input_8[2];  

        
        logic [3:0][31:0] p_x1_z5_8, p_x1_z14_8;
        assign p_x1_z5_8[3] = {p_8[0][26:0], p_8[0][31:27]}; 
        assign p_x1_z5_8[2] = {p_8[3][26:0], p_8[3][31:27]}; 
        assign p_x1_z5_8[1] = {p_8[2][26:0], p_8[2][31:27]}; 
        assign p_x1_z5_8[0] = {p_8[1][26:0], p_8[1][31:27]};

        assign p_x1_z14_8[3] ={p_8[0][17:0], p_8[0][31:18]};
        assign p_x1_z14_8[2] ={p_8[3][17:0], p_8[3][31:18]}; 
        assign p_x1_z14_8[1] ={p_8[2][17:0], p_8[2][31:18]}; 
        assign p_x1_z14_8[0] ={p_8[1][17:0], p_8[1][31:18]};  

        assign e_8 = p_x1_z5_8^p_x1_z14_8;

        logic [2:0][3:0][31:0] theta_out_8;

        assign theta_out_8[2] = perm_input_8[2]^e_8;
        assign theta_out_8[1] = perm_input_8[1]^e_8;
        assign theta_out_8[0] = perm_input_8[0]^e_8;
        
        logic [2:0][3:0][31:0] rho_west_8;
        
        assign rho_west_8[2][3] = {theta_out_8[2][3][20:0] , theta_out_8[2][3][31:21]};
        assign rho_west_8[2][2] = {theta_out_8[2][2][20:0] , theta_out_8[2][2][31:21]};
        assign rho_west_8[2][1] = {theta_out_8[2][1][20:0] , theta_out_8[2][1][31:21]};
        assign rho_west_8[2][0] = {theta_out_8[2][0][20:0] , theta_out_8[2][0][31:21]};

        assign rho_west_8[1][3] = theta_out_8[1][0];
        assign rho_west_8[1][2] = theta_out_8[1][3];
        assign rho_west_8[1][1] = theta_out_8[1][2];
        assign rho_west_8[1][0] = theta_out_8[1][1];
        
assign rho_west_8[0][3] = theta_out_8[0][3] ^ {32'h380}; 
          assign rho_west_8[0][2] = theta_out_8[0][2]; 
          assign rho_west_8[0][1] = theta_out_8[0][1]; 
assign rho_west_8[0][0] = theta_out_8[0][0];

        logic [2:0][3:0][31:0] chi_out_8;

        assign chi_out_8[2] = rho_west_8[2]^(rho_west_8[1]&~rho_west_8[0]);
        assign chi_out_8[1] = rho_west_8[1]^(rho_west_8[0]&~rho_west_8[2]);
        assign chi_out_8[0] = rho_west_8[0]^(rho_west_8[2]&~rho_west_8[1]);
        
        logic [2:0][3:0][31:0] rho_east_8;

        assign rho_east_8[2][3] = {chi_out_8[2][1][23:0], chi_out_8[2][1][31:24]};
        assign rho_east_8[2][2] = {chi_out_8[2][0][23:0], chi_out_8[2][0][31:24]};
        assign rho_east_8[2][1] = {chi_out_8[2][3][23:0], chi_out_8[2][3][31:24]};
        assign rho_east_8[2][0] = {chi_out_8[2][2][23:0], chi_out_8[2][2][31:24]};

        assign rho_east_8[1][3] = {chi_out_8[1][3][30:0], chi_out_8[1][3][31]};  
        assign rho_east_8[1][2] = {chi_out_8[1][2][30:0], chi_out_8[1][2][31]};
        assign rho_east_8[1][1] = {chi_out_8[1][1][30:0], chi_out_8[1][1][31]};
        assign rho_east_8[1][0] = {chi_out_8[1][0][30:0], chi_out_8[1][0][31]};
       
       assign rho_east_8[0] = chi_out_8[0];

        logic [383:0] round_out_8;
        
        assign round_out_8 = rho_east_8;

        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round nine///////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////

        logic [3:0][31:0] p_9, e_9; 
        logic [2:0][3:0][31:0] perm_input_9;

        assign perm_input_9 = round_out_8;
        assign p_9 =  perm_input_9[0]^perm_input_9[1]^perm_input_9[2];  

        
        logic [3:0][31:0] p_x1_z5_9, p_x1_z14_9;
        assign p_x1_z5_9[3] = {p_9[0][26:0], p_9[0][31:27]}; 
        assign p_x1_z5_9[2] = {p_9[3][26:0], p_9[3][31:27]}; 
        assign p_x1_z5_9[1] = {p_9[2][26:0], p_9[2][31:27]}; 
        assign p_x1_z5_9[0] = {p_9[1][26:0], p_9[1][31:27]};

        assign p_x1_z14_9[3] ={p_9[0][17:0], p_9[0][31:18]};
        assign p_x1_z14_9[2] ={p_9[3][17:0], p_9[3][31:18]}; 
        assign p_x1_z14_9[1] ={p_9[2][17:0], p_9[2][31:18]}; 
        assign p_x1_z14_9[0] ={p_9[1][17:0], p_9[1][31:18]};  

        assign e_9 = p_x1_z5_9^p_x1_z14_9;

        logic [2:0][3:0][31:0] theta_out_9;

        assign theta_out_9[2] = perm_input_9[2]^e_9;
        assign theta_out_9[1] = perm_input_9[1]^e_9;
        assign theta_out_9[0] = perm_input_9[0]^e_9;

        logic [2:0][3:0][31:0] rho_west_9;

        assign rho_west_9[2][3] = {theta_out_9[2][3][20:0] , theta_out_9[2][3][31:21]};
        assign rho_west_9[2][2] = {theta_out_9[2][2][20:0] , theta_out_9[2][2][31:21]};
        assign rho_west_9[2][1] = {theta_out_9[2][1][20:0] , theta_out_9[2][1][31:21]};
        assign rho_west_9[2][0] = {theta_out_9[2][0][20:0] , theta_out_9[2][0][31:21]};

        assign rho_west_9[1][3] = theta_out_9[1][0];
        assign rho_west_9[1][2] = theta_out_9[1][3];
        assign rho_west_9[1][1] = theta_out_9[1][2];
        assign rho_west_9[1][0] = theta_out_9[1][1];
        
assign rho_west_9[0][3] = theta_out_9[0][3] ^ {32'hf0}; 
          assign rho_west_9[0][2] = theta_out_9[0][2]; 
          assign rho_west_9[0][1] = theta_out_9[0][1]; 
assign rho_west_9[0][0] = theta_out_9[0][0];
          
        logic [2:0][3:0][31:0] chi_out_9;

        assign chi_out_9[2] = rho_west_9[2]^(rho_west_9[1]&~rho_west_9[0]);
        assign chi_out_9[1] = rho_west_9[1]^(rho_west_9[0]&~rho_west_9[2]);
        assign chi_out_9[0] = rho_west_9[0]^(rho_west_9[2]&~rho_west_9[1]);
        
        
        logic [2:0][3:0][31:0] rho_east_9;
        
        assign rho_east_9[2][3] = {chi_out_9[2][1][23:0], chi_out_9[2][1][31:24]};
        assign rho_east_9[2][2] = {chi_out_9[2][0][23:0], chi_out_9[2][0][31:24]};
        assign rho_east_9[2][1] = {chi_out_9[2][3][23:0], chi_out_9[2][3][31:24]};
        assign rho_east_9[2][0] = {chi_out_9[2][2][23:0], chi_out_9[2][2][31:24]};

        assign rho_east_9[1][3] = {chi_out_9[1][3][30:0], chi_out_9[1][3][31]};  
        assign rho_east_9[1][2] = {chi_out_9[1][2][30:0], chi_out_9[1][2][31]};
        assign rho_east_9[1][1] = {chi_out_9[1][1][30:0], chi_out_9[1][1][31]};
        assign rho_east_9[1][0] = {chi_out_9[1][0][30:0], chi_out_9[1][0][31]};
       
       assign rho_east_9[0] = chi_out_9[0];

        logic [383:0] round_out_9;
        
        assign round_out_9 = rho_east_9;


        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round a//////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        logic [3:0][31:0] p_a, e_a; 
        logic [2:0][3:0][31:0] perm_input_a;

        assign perm_input_a = round_out_9;
        assign p_a =  perm_input_a[0]^perm_input_a[1]^perm_input_a[2];  

        
        logic [3:0][31:0] p_x1_z5_a, p_x1_z14_a;
        assign p_x1_z5_a[3] = {p_a[0][26:0], p_a[0][31:27]}; 
        assign p_x1_z5_a[2] = {p_a[3][26:0], p_a[3][31:27]}; 
        assign p_x1_z5_a[1] = {p_a[2][26:0], p_a[2][31:27]}; 
        assign p_x1_z5_a[0] = {p_a[1][26:0], p_a[1][31:27]};

        assign p_x1_z14_a[3] ={p_a[0][17:0], p_a[0][31:18]};
        assign p_x1_z14_a[2] ={p_a[3][17:0], p_a[3][31:18]}; 
        assign p_x1_z14_a[1] ={p_a[2][17:0], p_a[2][31:18]}; 
        assign p_x1_z14_a[0] ={p_a[1][17:0], p_a[1][31:18]};  

        assign e_a = p_x1_z5_a^p_x1_z14_a;

        logic [2:0][3:0][31:0] theta_out_a;

        assign theta_out_a[2] = perm_input_a[2]^e_a;
        assign theta_out_a[1] = perm_input_a[1]^e_a;
        assign theta_out_a[0] = perm_input_a[0]^e_a;

        logic [2:0][3:0][31:0] rho_west_a;

        assign rho_west_a[2][3] = {theta_out_a[2][3][20:0] , theta_out_a[2][3][31:21]};
        assign rho_west_a[2][2] = {theta_out_a[2][2][20:0] , theta_out_a[2][2][31:21]};
        assign rho_west_a[2][1] = {theta_out_a[2][1][20:0] , theta_out_a[2][1][31:21]};
        assign rho_west_a[2][0] = {theta_out_a[2][0][20:0] , theta_out_a[2][0][31:21]};

        assign rho_west_a[1][3] = theta_out_a[1][0];
        assign rho_west_a[1][2] = theta_out_a[1][3];
        assign rho_west_a[1][1] = theta_out_a[1][2];
        assign rho_west_a[1][0] = theta_out_a[1][1];
        
assign rho_west_a[0][3] = theta_out_a[0][3] ^ {32'h1a0}; 
          assign rho_west_a[0][2] = theta_out_a[0][2]; 
          assign rho_west_a[0][1] = theta_out_a[0][1]; 
assign rho_west_a[0][0] = theta_out_a[0][0];
          

        logic [2:0][3:0][31:0] chi_out_a;

        assign chi_out_a[2] = rho_west_a[2]^(rho_west_a[1]&~rho_west_a[0]);
        assign chi_out_a[1] = rho_west_a[1]^(rho_west_a[0]&~rho_west_a[2]);
        assign chi_out_a[0] = rho_west_a[0]^(rho_west_a[2]&~rho_west_a[1]);
        
        logic [2:0][3:0][31:0] rho_east_a;

        assign rho_east_a[2][3] = {chi_out_a[2][1][23:0], chi_out_a[2][1][31:24]};
        assign rho_east_a[2][2] = {chi_out_a[2][0][23:0], chi_out_a[2][0][31:24]};
        assign rho_east_a[2][1] = {chi_out_a[2][3][23:0], chi_out_a[2][3][31:24]};
        assign rho_east_a[2][0] = {chi_out_a[2][2][23:0], chi_out_a[2][2][31:24]};

        assign rho_east_a[1][3] = {chi_out_a[1][3][30:0], chi_out_a[1][3][31]};  
        assign rho_east_a[1][2] = {chi_out_a[1][2][30:0], chi_out_a[1][2][31]};
        assign rho_east_a[1][1] = {chi_out_a[1][1][30:0], chi_out_a[1][1][31]};
        assign rho_east_a[1][0] = {chi_out_a[1][0][30:0], chi_out_a[1][0][31]};
       
       assign rho_east_a[0] = chi_out_a[0];

        logic [383:0] round_out_a;
        
        assign round_out_a = rho_east_a;    

        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round b//////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        logic [3:0][31:0] p_b, e_b; 
        logic [2:0][3:0][31:0] perm_input_b;

        assign perm_input_b = round_out_a;
        assign p_b =  perm_input_b[0]^perm_input_b[1]^perm_input_b[2];  

        
        logic [3:0][31:0] p_x1_z5_b, p_x1_z14_b;
        assign p_x1_z5_b[3] = {p_b[0][26:0], p_b[0][31:27]}; 
        assign p_x1_z5_b[2] = {p_b[3][26:0], p_b[3][31:27]}; 
        assign p_x1_z5_b[1] = {p_b[2][26:0], p_b[2][31:27]}; 
        assign p_x1_z5_b[0] = {p_b[1][26:0], p_b[1][31:27]};

        assign p_x1_z14_b[3] ={p_b[0][17:0], p_b[0][31:18]};
        assign p_x1_z14_b[2] ={p_b[3][17:0], p_b[3][31:18]}; 
        assign p_x1_z14_b[1] ={p_b[2][17:0], p_b[2][31:18]}; 
        assign p_x1_z14_b[0] ={p_b[1][17:0], p_b[1][31:18]};  

        assign e_b = p_x1_z5_b^p_x1_z14_b;

        logic [2:0][3:0][31:0] theta_out_b;

        assign theta_out_b[2] = perm_input_b[2]^e_b;
        assign theta_out_b[1] = perm_input_b[1]^e_b;
        assign theta_out_b[0] = perm_input_b[0]^e_b;
        
        logic [2:0][3:0][31:0] rho_west_b;

        assign rho_west_b[2][3] = {theta_out_b[2][3][20:0] , theta_out_b[2][3][31:21]};
        assign rho_west_b[2][2] = {theta_out_b[2][2][20:0] , theta_out_b[2][2][31:21]};
        assign rho_west_b[2][1] = {theta_out_b[2][1][20:0] , theta_out_b[2][1][31:21]};
        assign rho_west_b[2][0] = {theta_out_b[2][0][20:0] , theta_out_b[2][0][31:21]};

        assign rho_west_b[1][3] = theta_out_b[1][0];
        assign rho_west_b[1][2] = theta_out_b[1][3];
        assign rho_west_b[1][1] = theta_out_b[1][2];
        assign rho_west_b[1][0] = theta_out_b[1][1];
        
assign rho_west_b[0][3] = theta_out_b[0][3] ^ {32'h12}; 
          assign rho_west_b[0][2] = theta_out_b[0][2]; 
          assign rho_west_b[0][1] = theta_out_b[0][1]; 
assign rho_west_b[0][0] = theta_out_b[0][0];// ^ CIBOX[rnd_cnt]; Should be this one but it's not.  
          

        logic [2:0][3:0][31:0] chi_out_b;

        assign chi_out_b[2] = rho_west_b[2]^(rho_west_b[1]&~rho_west_b[0]);
        assign chi_out_b[1] = rho_west_b[1]^(rho_west_b[0]&~rho_west_b[2]);
        assign chi_out_b[0] = rho_west_b[0]^(rho_west_b[2]&~rho_west_b[1]);
        
        logic [2:0][3:0][31:0] rho_east_b;

        assign rho_east_b[2][3] = {chi_out_b[2][1][23:0], chi_out_b[2][1][31:24]};
        assign rho_east_b[2][2] = {chi_out_b[2][0][23:0], chi_out_b[2][0][31:24]};
        assign rho_east_b[2][1] = {chi_out_b[2][3][23:0], chi_out_b[2][3][31:24]};
        assign rho_east_b[2][0] = {chi_out_b[2][2][23:0], chi_out_b[2][2][31:24]};

        assign rho_east_b[1][3] = {chi_out_b[1][3][30:0], chi_out_b[1][3][31]};  
        assign rho_east_b[1][2] = {chi_out_b[1][2][30:0], chi_out_b[1][2][31]};
        assign rho_east_b[1][1] = {chi_out_b[1][1][30:0], chi_out_b[1][1][31]};
        assign rho_east_b[1][0] = {chi_out_b[1][0][30:0], chi_out_b[1][0][31]};
       
        assign rho_east_b[0] = chi_out_b[0];

        logic [383:0] round_out_b;
        
        assign round_out_b = rho_east_b;    
        
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        //Round b was the last round.  The bits are now reconcatenated for output//////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////

        
        logic [383:0] perm_reconcat;
        assign perm_reconcat = {  round_out_b[103:96] ,round_out_b[111:104],round_out_b[119:112],round_out_b[127:120],
                                  round_out_b[71:64]  ,round_out_b[79:72]  ,round_out_b[87:80]  ,round_out_b[95:88],
                                  round_out_b[39:32]  ,round_out_b[47:40]  ,round_out_b[55:48]  ,round_out_b[63:56],
                                  round_out_b[7:0]    ,round_out_b[15:8]   ,round_out_b[23:16]  ,round_out_b[31:24],                          
                                  
                                  round_out_b[231:224],round_out_b[239:232],round_out_b[247:240],round_out_b[255:248],
                                  round_out_b[199:192],round_out_b[207:200],round_out_b[215:208],round_out_b[223:216],
                                  round_out_b[167:160],round_out_b[175:168],round_out_b[183:176],round_out_b[191:184],
                                  round_out_b[135:128],round_out_b[143:136],round_out_b[151:144],round_out_b[159:152],
                                  
                                  round_out_b[359:352],round_out_b[367:360], round_out_b[375:368], round_out_b[383:376],
                                  round_out_b[327:320],round_out_b[335:328],round_out_b[343:336],round_out_b[351:344],
                                  round_out_b[295:288],round_out_b[303:296],round_out_b[311:304],round_out_b[319:312],
                                  round_out_b[263:256],round_out_b[271:264],round_out_b[279:272],round_out_b[287:280]
                                };

        //Output is registered for timing purposes.  
        
  //rregs_en #(384,1) permstate (state_out, perm_reconcat, eph1,start); //Will have to redefine the register when I get a better idea of how it will work. 
assign state_out = perm_reconcat;
        endmodule: permute

     