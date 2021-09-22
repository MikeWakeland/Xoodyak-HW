    module absorb #(parameter PERM_CTR=3)(
				input logic eph1,
				input logic reset,
				input logic start,
				
				input logic [1:0]		absorb_usr,  //bit 1: user says whether there is more data after this one (1 = yes).  Bit 0: user says whether we are starting (1 = yes).  
				input logic [351:0] absorb_input,
				input logic [383:0] state_initial, //This is the state after the absorbkey function.  
				input logic [383:0] state_in,
				input logic [383:0] state_out,
				
				output logic [383:0] absorb_to_permute, //pushes the absorb state to permute
				input  logic [383:0] permute_to_absorb, //recovers the permuted state in absorb 
				
				output logic [383:0] absorbed_state,
				output logic 				 absorb_complete
				
				
				);
				
				
	///			logic [351:0] absorb_input_r;
				logic [383:0] absorb_down;
				
				
				
//        rregs_en #(352,1) absrbin  ( absorb_input_r		 , absorb_input       , eph1, start | still_absorb);


				assign absorb_down = {absorb_input^permute_to_absorb[383:32], permute_to_absorb[31:25], ~permute_to_absorb[24] , permute_to_absorb[23:2], ~permute_to_absorb[1:0]};

		
		//rregs_en (384,1) absout = (absorbed_state, absorb_down, eph1, ~absorb_usr[1] & ( PERM_CTR == '0);  //this line is NOT an output and needs to be registered.  


		assign absorb_to_permute = absorb_usr[0] ? state_initial : absorb_down ;
				
/*         
          //This performs the absorb manipulation required on the permute output:
          //For DOWN(extra_data,8'h03)
          logic [383:0] state_temp, cryptout; 
          logic [127:0] extra_data;
          
          assign extra_data = sm_asso ? assodata_r : sm_nonce_r ;
          assign state_temp = extra_data^permute_out[383:256]; //Absorbs the nonce or AD from bytes 0-15 inclusive
          // perm_out ^ (Xi||8'h01||'00(extended)||Cd)  Cd is 8'h03.  
          assign absorb_out = {state_temp, permute_out[255:249], ~permute_out[248] ,permute_out[247:2], ~permute_out[1:0]};

 */

endmodule: absorb