
/* 
    module xoodyaktop(
      input logic [191:0] plaintext,
      input logic [127:0] nonce,
      input logic [127:0] key,

      output logic [127:0] authdata,
      output logic [191:0]   ciphertext,
      output logic          encdone

    );

    logic [383:0] state_initial;

    assign state_initial = {key,8'h01, 256'h0, 8'h2};
    absorb absorbnonce(
    //instance whatever
    );

    absorb absorbauthdata(
    //instance whatever
    //should be wired directly to nonce.  
    );

    encyrpt encrypt(
    //does the encryption
    ); 

    endmodule: xoodyaktop


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    module encrypt(

      input logic [383:0] state,
      input logic [191:0] plaintext,
      
      output logic [191:0] ciphertext,
      output logic [127:0] authdata

    );

    //let's start with just the short message version.  
    logic [383:0] state_enc,enc_permd;
    logic encpermflag;

    assign state_enc = {state[383:8],~state[7],state[6:0]}; //XORS domain value 0x80 with the state upon start of encrytion. 

    round etcwhatever (

    .state_in (state_enc),
    .state_out (enc_permd),
    .xood_done (encpermflag)
    );

    //XORS up to 192' of message with the state.  
    //assumption: xor'ing with the 192 MSB of the state.

    assign ciphertext = plaintext ^ enc_permd[383:192];

    logic [127:0] final_authtag
    
    squeeze squeezetag(
      .state   (enc_permd),
      .authtag ( final_authtag)
    );

    assign ciphertext = enc_vec;
    assign authdata   = final_authtag;
    assign encdone = ;//whenever we're done with both generating the ciphertext and the authdata

    endmodule: encrypt 

 */


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    module permute( //Maybe I should be registering at the end of every instance of round for timing. 
		//Per the xoodoo cookbook, array indices are (z+32*(x+4y)), where y is the plane, x is the lane, and z is the depth of the lane. 

			input logic 				eph1,
			input logic					reset, 
			input logic 				start,
      input logic  [383:0] state_in,  //Indicies: plane, lane, zed
      
      output logic [383:0] state_out,
      output logic xood_done 

    );

    //Lookup table Fake for now.  There doesn't appear to be a functional difference between 128' and, 2+4+4 = 10 bits here...
    const logic [12:1][127:0] CIBOX = '{ 32'h58, 32'h38, 32'h3c0, 32'hD0, 32'h120, 32'h14, 
		32'h60, 32'h2c, 32'h380, 32'hF0, 32'h1A0, 32'h12}; //May need to revese

    logic [3:0] rnd_cnt, rnd_cnt_next;
    //fake counter, will be replaced by direct evaluation.  
    initial rnd_cnt = 12;
    assign rnd_cnt_next = rnd_cnt - 1;  
    rregs #(4) xooctr (rnd_cnt, rnd_cnt_next,eph1);
    assign xood_done = (rnd_cnt == 4'h0);
		logic [2:0][3:0][31:0] rnd_recycle; 
		logic [383:0] bits_in, bits_le;
    logic [2:0][3:0][31:0] perm_in ; //Indicies: plane, lane, zed
    //Traditioanl formatting: assign perm_in = state_in;
		
		assign bits_in = (rnd_cnt == 11) ? state_in : rnd_recycle; 
		assign bits_le = {bits_in[359:352], bits_in[367:360], bits_in[375:368], bits_in[383:376],
											bits_in[327:320],bits_in[335:328],bits_in[343:336],bits_in[351:344],
											bits_in[295:288],bits_in[303:296],bits_in[311:304],bits_in[319:312],
											bits_in[263:256],bits_in[271:264],bits_in[279:272],bits_in[287:280],
											bits_in[231:224],bits_in[239:232],bits_in[247:240],bits_in[255:248],
											bits_in[199:192],bits_in[207:200],bits_in[215:208],bits_in[223:216],
											bits_in[167:160],bits_in[175:168],bits_in[183:176],bits_in[191:184],
											bits_in[135:128],bits_in[143:136],bits_in[151:144],bits_in[159:152],
											bits_in[103:96] ,bits_in[111:104],bits_in[119:112],bits_in[127:120],
											bits_in[71:64]  ,bits_in[79:72]  ,bits_in[87:80]  ,bits_in[95:88],
											bits_in[39:32]  ,bits_in[47:40]  ,bits_in[55:48]  ,bits_in[63:56],
											bits_in[7:0]    ,bits_in[15:8]   ,bits_in[23:16]  ,bits_in[31:24]};

    //Round zero

    //Theta input
    logic [3:0][31:0] p, e; //Indicies: lane, zed.
		logic [2:0][3:0][31:0] rnd_input;

		assign rnd_input = (rnd_cnt == 11) ? bits_le : rnd_recycle;
    assign p =  rnd_input[0]^rnd_input[1]^rnd_input[2];  //Will need to make a better version later.  

    //write as function perhaps191
    logic [3:0][31:0] p_x1_z5, p_x1_z14;
    assign p_x1_z5[3] = {p[0][26:0], p[0][31:27]}; 
    assign p_x1_z5[2] = {p[3][26:0], p[3][31:27]}; 
    assign p_x1_z5[1] = {p[2][26:0], p[2][31:27]}; 
    assign p_x1_z5[0] = {p[1][26:0], p[1][31:27]};

    assign p_x1_z14[3] ={p[0][17:0], p[0][31:18]};
    assign p_x1_z14[2] ={p[3][17:0], p[3][31:18]}; 
    assign p_x1_z14[1] ={p[2][17:0], p[2][31:18]}; 
    assign p_x1_z14[0] ={p[1][17:0], p[1][31:18]};  

    assign e = p_x1_z5^p_x1_z14;

    logic [2:0][3:0][31:0] theta_out;

    assign theta_out[2] = rnd_input[2]^e;
    assign theta_out[1] = rnd_input[1]^e;
    assign theta_out[0] = rnd_input[0]^e;

    //rho and constant add
		//Reversed the lefthandside arguments since I think
		//They are backwards for software.  
		//Specifically, they are flipped across the plane[1] axis
		//So planes [2] and [0] are reversed, but not [1]
		
    logic [2:0][3:0][31:0] rho_west;

 //Version with z shifts.
    assign rho_west[0][3] = {theta_out[0][3][20:0] , theta_out[0][3][31:21]};
    assign rho_west[0][2] = {theta_out[0][2][20:0] , theta_out[0][2][31:21]};
    assign rho_west[0][1] = {theta_out[0][1][20:0] , theta_out[0][1][31:21]};
    assign rho_west[0][0] = {theta_out[0][0][20:0] , theta_out[0][0][31:21]};


/*  assign rho_west[2][3] = theta_out[2][3]; //No shifts at all
    assign rho_west[2][2] = theta_out[2][2];
    assign rho_west[2][1] = theta_out[2][1];
    assign rho_west[2][0] = theta_out[2][0]; */

    assign rho_west[1][3] = theta_out[1][0];
    assign rho_west[1][2] = theta_out[1][3];
    assign rho_west[1][1] = theta_out[1][2];
    assign rho_west[1][0] = theta_out[1][1];

    //Functionally adds the round constant of 32'h58 to the round.  
    //Potentially add the round key at the very end191 
    //Replace lookup table with direct evaluation at the end.


			logic [31:0] const_wire;
			
			assign const_wire = CIBOX[rnd_cnt+1];
			
			//The python script definitely doesn't lookup anything except the first set
			//Per the tech standard, it should be modifiying rho_west[0][0] instead but endianness is getting in the way.  
      assign rho_west[2][3] = theta_out[2][3]^ CIBOX[rnd_cnt+1];
      assign rho_west[2][2] = theta_out[2][2]; 
      assign rho_west[2][1] = theta_out[2][1]; 
      assign rho_west[2][0] = theta_out[2][0] ; //^ CIBOX[rnd_cnt]; 
			
			
			
    /*Boolean equivalent.
     assign rho_west[0][3] = {theta_out[0][3][31:7], ~theta_out[0][3][6], theta_out[0][3][5], ~theta_out[0][3][4:3], theta_out[0][3][2:0]} ;
    assign rho_west[0][2] = {theta_out[0][2][31:7], ~theta_out[0][2][6], theta_out[0][2][5], ~theta_out[0][2][4:3], theta_out[0][2][2:0]} ;
    assign rho_west[0][1] = {theta_out[0][1][31:7], ~theta_out[0][1][6], theta_out[0][1][5], ~theta_out[0][1][4:3], theta_out[0][1][2:0]} ;
    assign rho_west[0][0] = {theta_out[0][0][31:7], ~theta_out[0][0][6], theta_out[0][0][5], ~theta_out[0][0][4:3], theta_out[0][0][2:0]} ; */


    //Chi section
/* 
    assign rho_west_c[2][3] = ~theta_out[2][0];
    assign rho_west_c[2][2] = ~theta_out[2][3];
    assign rho_west_c[2][1] = ~theta_out[2][2];
    assign rho_west_c[2][0] = ~theta_out[2][1];

    assign rho_west_c[1][3] = ~theta_out[1][0];
    assign rho_west_c[1][2] = ~theta_out[1][3];
    assign rho_west_c[1][1] = ~theta_out[1][2];
    assign rho_west_c[1][0] = ~theta_out[1][1];
 */
    //Functionally adds the round constant of 32'h58 to the round.  
    /* 
    assign rho_west_c[0][3] = {~theta_out[0][3][31:7], theta_out[0][3][6], ~theta_out[0][3][5], theta_out[0][3][4:3], ~theta_out[0][3][2:0]} ;
    assign rho_west_c[0][2] = {~theta_out[0][2][31:7], theta_out[0][2][6], ~theta_out[0][2][5], theta_out[0][2][4:3], ~theta_out[0][2][2:0]} ;
    assign rho_west_c[0][1] = {~theta_out[0][1][31:7], theta_out[0][1][6], ~theta_out[0][1][5], theta_out[0][1][4:3], ~theta_out[0][1][2:0]} ;
    assign rho_west_c[0][0] = {~theta_out[0][0][31:7], theta_out[0][0][6], ~theta_out[0][0][5], theta_out[0][0][4:3], ~theta_out[0][0][2:0]} ;
     */
    logic [2:0][3:0][31:0] chi_out;

    assign chi_out[2] = rho_west[2]^(~rho_west[1]&rho_west[0]);
    assign chi_out[1] = rho_west[1]^(~rho_west[0]&rho_west[2]);
    assign chi_out[0] = rho_west[0]^(~rho_west[2]&rho_west[1]);
		
    //Rho_east
    logic [2:0][3:0][31:0] rho_east;

		//Having rho_east oriented this way allows it to match up with the software, but 
		//technically the second plane should be undergoing these manipulations, 
		//so both the rho east and chi_out are flipped across the plane [1] axis.  
    assign rho_east[0][3] = {chi_out[0][1][23:0], chi_out[0][1][31:24]};
    assign rho_east[0][2] = {chi_out[0][0][23:0], chi_out[0][0][31:24]};
    assign rho_east[0][1] = {chi_out[0][3][23:0], chi_out[0][3][31:24]};
    assign rho_east[0][0] = {chi_out[0][2][23:0], chi_out[0][2][31:24]};

    assign rho_east[1][3] = {chi_out[1][3][30:0], chi_out[1][3][31]};  
		assign rho_east[1][2] = {chi_out[1][2][30:0], chi_out[1][2][31]};
		assign rho_east[1][1] = {chi_out[1][1][30:0], chi_out[1][1][31]};
		assign rho_east[1][0] = {chi_out[1][0][30:0], chi_out[1][0][31]};
   
	 assign rho_east[2] = chi_out[2];

    assign state_out = rho_east;

		
		rregs  #(384) rndwire (rnd_recycle ,state_out,eph1);
		logic [11:0][31:0] state_wiretap;
		assign state_wiretap = state_out;




    endmodule: permute

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    module absorb (
		
	  	input logic 				eph1,
			input logic					reset, 
			input logic 				start,
		
      input logic  [383:0] state_in,
      input logic  [127:0] extra_data, //can be either associated data or the nonce. 

      output logic [383:0] state_out,
      output logic         absorb_done
    );

    logic [383:0] perm_out;
    logic [135:0] state_temp;
    logic       perm_done;



    permute absorbround(
		.eph1			 (eph1),
		.reset		 (reset),
		.start		 (start),
    .state_in  (state_in),
    .state_out (perm_out),
    .xood_done (perm_done)
    );

    //Critically, I don't know what order I'm XORing, so the array indices may be backwards here.  Assuming I'm starting at C index 0 = msb
    assign state_temp[135:8] = extra_data^perm_out[383:256]; //Absorbs the nonce or AD from bytes 0-15 inclusive
    assign state_temp[7:0] = {perm_out[255:249], ~perm_out[248]}; //XOR's 0x01 with byte 16


    //Set phase_down, if applicable (per the standard but may not be useful in HW)

    assign state_out = {state_temp, perm_out[255:0]};

    //assign absorb_done = something, idk?;


    endmodule: absorb
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    module squeeze (
		
	 	 input logic 				eph1,
			input logic					reset, 
			input logic 				start,

      input logic [383:0] state,
      output logic [127:0] authtag

    );
    logic [383:0] perm_in, perm_out;
		logic perm_done;

    assign perm_in = {state[383:7], ~state[6], state[5:0]}; //computationally finds: 0x40 ^ state;

    permute sqzrnd(
		
		.eph1			 (eph1),
		.reset		 (reset),
		.start		 (start),
    .state_in  (state),
    .state_out (perm_out),
    .xood_done (perm_done)
		
    );

    assign authtag = perm_out[127:0]; //is it 127:0 or 383:255 191

    endmodule: squeeze
 