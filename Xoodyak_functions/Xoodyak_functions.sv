

      module xoodyak_build(
          input logic             eph1,
          input logic             reset,
          
          input logic [351:0]     input_data, 
          input logic [3:0]       opmode,    


          output logic            ready, 
          output logic [191:0]    textout_r,
          output logic            textout_valid
          
        );
        
        //Parameter definitions are on line 128 and 129.

                //----------------------------------------------------------------
                //Technical briefing on XOODYAK
                //----------------------------------------------------------------                
          /*    
           Timing: 
					 Xoodyak accepts inputs on the positive edge after ready is 1.    
           Xoodyak completes functions in either one clock, or four clocks. 
           There is a minimum of one clock spent in the idle state between function calls. This means that clock delays from data supply to data supply 
           are two, or five clocks depending on the function.
           
           Any function that calls the permute module completes in four clocks. Not every function call requires a permute.  Functions that end with an 
           "UP" state as defined by "Xoodyak - A Lightweight Encryption Scheme" cause the next function called to not use permute. Multiple calls to the 
           same function do not trigger this case.  For example, generating a 256' squeeze requires two sequential calls to squeeze.  Each call requires
           a permute, and two calls are required, for a total of ten clocks to generate the entire string.  A following Absorb() or other function will 
           not require a permute, and as such there is a 1 clock execution + 1 clock idle = 2 clock delay until the next set of data and function calls
           can be supplied.  
           
           functions which never require permute (two clock delays):
           (FUNCTION)       - (OPCODE)
            Cyclist (keyed) -  4'h1
            Cyclist (hash)  -  4'h9
 
           functions which terminate in an "UP" state (the next non identical function call is a two clock delay):
            (FUNCTION)      - (OPCODE)     
            Cyclist (hash)  -  4'h9
            Squeeze         -  4'h6
            Squeeze Key     -  4'h8
            
           functions which require permute (five clock delays), unless they began in an "UP" state:
            (FUNCTION)      - (OPCODE)
            Nonce           -  4'h2
            Absorb          -  4'h3
            Encrypt         -  4'h4
            Decrypt         -  4'h5
            Squeeze         -  4'h6
            Ratchet         -  4'h7
            Squeeze (key)   -  4'h8
           
          
           Example sequence of funtion calls:
  
           Example 1-
           clk (decimal)       function      
           0                   Cyclist (keyed) <- Cyclist calls create two clock delays.
           2                   Nonce 
           7                   Absorb
           12                  Encrypt
           17                  Squeeze
           22                  Absorb          <- Two clock delay because of the previous function terminating in an "UP" state.
           24                  Encrypt    
           29                  Squeeze (key) 
           
           Example 2-
           clk (decimal)       function 
           0                   Cyclist (hash)  <- Cyclist calls create two clock delays.
           2                   Absorb           <- Two clock delay because of the previous function terminating in an "UP" state.
           4                   Absorb  
           9                   Absorb
           14                  Squeeze
           19                  Squeeze
           24                  Squeeze
           29                  Cyclist (keyed)  <- Cyclist calls create two clock delays.
           31                  Nonce
           

          
           Important information:
           >If the function call decode is invalid the state remains in idle.  
           >Hashed/Keyed mode can only be changed during a call to the Cyclist instantiation.
           >A Hashed/Keyed mode must be established before any other function calls are made.  Resets wipe both modes.
           >The user can call any other sequence of functions, even if they are not meaningful.  cyclist() -> encrypt() -> decyrpt() is a valid, if illogical series of function calls.
           >Permute requires four clock cycles.  One clock in the idle state is required between function calls.  Thus, the start -> start time is 5 clocks.
           >Ratchet calls can only handle the 128' length call.  Theoretical maximum sequential function calls are unlimited, but may not have a purpose.  
           >Xoodyak is capable of other function calls after Squeeze(), and correctly handles whether the state is "up" or "down."  
           >If a function call is made after a function that ends with the state being "up" an exception triggers to perform a one clock function.
           
           Xoodyak requires:
           > Synchronized function calls and data.  
           >This build is capable of processing 192' multiples of plaintext and ciphertext.
           >Absorb data is taken in 352'/44byte increments.  The user is responsible for padding the input data.  
           >Nonce dada is taken in 128'/16byte increments.  The user is responsible for padding the input data.
           >Keys are 128'/16 bytes only.  Greater key lengths can be absorbed through either the nonce or absorb functions, subject to their length requirements.  
           >Align the data on the most significan bits of the input vector, with zeros on the least significant side. 
           
            
            Xoodyak produces:
          >Ciphertext and plaintext in increments of 192'. No theoretical maximum of sequential function calls.
          >Squeezes, tags, and keys in increments of 128'. No theoretical maximum of sequential function calls.
           The output text is alligned on the most significant bits for 128' outputs.  
          >A 1' signal to show inputs will be accepted on the next clock.            
          
            
                 
           */ 
      
            //----------------------------------------------------------------
            //XOODYAK's governing Finite State Machine  
            //
            //  The finite state machine is made up of four parts.  The sm_state_next, the sm_state, the shadow_state, and mode.
            //  The sm_state_next is based on opcode_r and associated logic, which determines which function (sm_state) the machine will enter on the next clock.
            //  Upon completing the function call the state will kick back to idle for a minimum of one clock cycle.  Direct calls from one function to another 
            //  are theoretically possible but not implemented.  
            //  
            //  The state remains constant for the duration of a function call, which is normally determined by the length of the permute function.  permute requires
            //  four clocks to complete. 
            //  
            //  The shadow_state is whatever state was previously called before the existing state, not counting sm_idle.  The shadow_state endures until the 
            //  return to idle state on the existing function call, at which point it is assigned the value of the function call just completed.  
            //  
            //  meta_shadow_cyc operates the same way as shadow_state, but only for cyclist.  It is used in an exception handle.  
            //  
            //  The mode can either be null, hash, or keyed.  It is null on reset.  hash/keyed modes are set upon calls to cyclist().  The mode endures until another
            //  call to cyclist.  Certain modes can only be called in keyed mode, and have different imput vector lengths in hash mode.            
            //----------------------------------------------------------------

              
          logic                    sm_idle,  sm_cyc, sm_run, sm_idle_next, sm_cyc_next,  sm_non_next, op_switch_next,
                                   sm_abs_next , sm_abs , sm_enc_next, sm_enc, sm_sqz_next, sm_sqz, sm_finish_next, run, sm_non, sm_dec_next, sm_dec,
                                   sm_rat, sm_rat_next, sm_sky, sm_sky_next, hash_mode, keyed_mode, initial_state, one_clock_functions, statechange, run_next, 
                                   shadow_cyc, shadow_non, shadow_abs, shadow_enc, shadow_dec, shadow_sqz, shadow_rat, shadow_sky,                           
                                   meta_cyc, permute_run_next;                         
          logic [4:0]              opmode_r; 
          parameter logic MUX = 1; 
          
          
           assign run =      sm_cyc      | sm_non      | sm_abs      | sm_enc       | sm_dec      | sm_sqz      | sm_sky      | sm_rat;
          assign run_next = sm_cyc_next | sm_non_next | sm_abs_next | sm_enc_next  | sm_dec_next | sm_sqz_next | sm_rat_next | sm_sky_next; //sm_non;
           assign initial_state = ~(shadow_cyc|shadow_non|shadow_abs|shadow_enc|shadow_dec|shadow_sqz|shadow_rat|shadow_sky);
          assign one_clock_functions = sm_cyc | (~sm_sqz&shadow_sqz)| (~sm_sky&shadow_sky) | (sm_abs&hash_mode&~shadow_abs&shadow_cyc) ;
          
          rregs_en #(1) hashmd_1 (hash_mode,  ~reset & opmode_r[3] & opmode[0] , eph1, sm_cyc_next|reset);
          rregs_en #(1) keymd_1  (keyed_mode, ~reset & ~(opmode_r[3]&opmode[0]), eph1, sm_cyc_next|reset); 

          assign sm_idle_next      =  (sm_idle & (~run_next) | (op_switch_next & run) | sm_cyc);
          assign sm_cyc_next       =  (sm_idle &((opmode_r[3:0] == 4'b1001) | (opmode_r[3:0] == 4'b0001)));        
          assign sm_non_next       = ((sm_idle & (opmode_r[3:0] == 4'b0010) & keyed_mode) | (sm_non   &  ~op_switch_next))&~initial_state; 
          assign sm_abs_next       = ((sm_idle & (opmode_r[3:0] == 4'b0011)             ) | (sm_abs   &  ~op_switch_next))&~initial_state; // Not Keymode only
          assign sm_enc_next       = ((sm_idle & (opmode_r[3:0] == 4'b0100) & keyed_mode) | (sm_enc   &  ~op_switch_next))&~initial_state;
          assign sm_dec_next       = ((sm_idle & (opmode_r[3:0] == 4'b0101) & keyed_mode) | (sm_dec   &  ~op_switch_next))&~initial_state; 
          assign sm_sqz_next       = ((sm_idle & (opmode_r[3:0] == 4'b0110)             ) | (sm_sqz   &  ~op_switch_next))&~initial_state; //Not keyed mode only.
          assign sm_rat_next       = ((sm_idle & (opmode_r[3:0] == 4'b0111) & keyed_mode) | (sm_rat   &  ~op_switch_next))&~initial_state; 
          assign sm_sky_next       = ((sm_idle & (opmode_r[3:0] == 4'b1000) & keyed_mode) | (sm_sky   &  ~op_switch_next))&~initial_state; 
                   
               
          rregs #(1) smir_2 (sm_idle,    reset | sm_idle_next,   eph1);
          rregs #(1) smsr_2 (sm_cyc,    ~reset & sm_cyc_next,    eph1);
          rregs #(1) smno_4 (sm_non,    ~reset & sm_non_next,    eph1); 
          rregs #(1) smas_4 (sm_abs,    ~reset & sm_abs_next,    eph1);
          rregs #(1) smen_4 (sm_enc,    ~reset & sm_enc_next,    eph1);
          rregs #(1) smde_4 (sm_dec,    ~reset & sm_dec_next,    eph1);        
          rregs #(1) smsq_4 (sm_sqz,    ~reset & sm_sqz_next,    eph1);
          rregs #(1) smra_4 (sm_rat,    ~reset & sm_rat_next,    eph1);
          rregs #(1) smsk_4 (sm_sky,    ~reset & sm_sky_next,    eph1);       
      
        
          rregs_en #(1,MUX) shdwcyc_3      (shadow_cyc , ~reset&sm_cyc      , eph1,  reset|((op_switch_next|sm_cyc)&~sm_idle));
          rregs_en #(1,MUX) shdwnon_9      (shadow_non , ~reset&sm_non      , eph1,  reset|(op_switch_next&~sm_idle));
          rregs_en #(1,MUX) shdwabs_5h_8k  (shadow_abs , ~reset&sm_abs      , eph1,  reset|(op_switch_next&~sm_idle));     
          rregs_en #(1,MUX) shdwenc_9      (shadow_enc , ~reset&sm_enc      , eph1,  reset|(op_switch_next&~sm_idle));     
          rregs_en #(1,MUX) shdwdec_9      (shadow_dec , ~reset&sm_dec      , eph1,  reset|(op_switch_next&~sm_idle));            
          rregs_en #(1,MUX) shdwsqz_9      (shadow_sqz , ~reset&sm_sqz      , eph1,  reset|(op_switch_next&~sm_idle));
          rregs_en #(1,MUX) shdwsky_9      (shadow_sky , ~reset&sm_sky      , eph1,  reset|(op_switch_next&~sm_idle));
          rregs_en #(1,MUX) shdwrat_9      (shadow_rat , ~reset&sm_rat      , eph1,  reset|(op_switch_next&~sm_idle));        
          
            
          //I created the meta state to track function calls before the previous one, however only the meta_cyc state was used.  So I deleted the others.    
          rregs_en #(1,MUX) metacyc_5h_8k (meta_cyc , ~reset&shadow_cyc      , eph1,  reset|((op_switch_next|sm_cyc)&~sm_idle));

         assign statechange = sm_idle&(sm_cyc_next | sm_non_next | sm_abs_next | sm_enc_next | sm_dec_next | sm_sqz_next | sm_sky_next | sm_rat_next); //sets the perm counter to three whenever there's a state change on the next clock. 
   
            //----------------------------------------------------------------
            //State Counters.  Counts how many clocks remain before a state change. 
            //----------------------------------------------------------------   
          
          logic [2:0] perm_ctr,  perm_ctr_next;      

          parameter logic [2:0] PERM_INIT = 3'h3;   
          
          assign permute_run_next = ~(sm_idle_next|one_clock_functions);
          assign op_switch_next = (perm_ctr == 3'h0) | one_clock_functions; 
          assign perm_ctr_next = perm_ctr - 1; 
                    
          rregs_en #(3,MUX) permc_4 (perm_ctr, (reset | statechange ) ? PERM_INIT : perm_ctr_next, eph1, run_next|reset);  
         

            //----------------------------------------------------------------
            //Output flags. Synchronizes outputs for sqzdone and encdone.  
            //----------------------------------------------------------------  
          rregs_en #(192, MUX) texttrial_9 (textout_r, reset? '0: textout_sel, eph1, sm_idle_next|reset);  

          rregs_en #(1, MUX) txtutr ( textout_valid , ~reset&(sm_enc|sm_dec|sm_sqz|sm_sky), eph1, sm_idle_next); 
          assign ready = sm_idle_next; //"Opcodes and data supplied will be registered for use on the clock after this is up."

            //----------------------------------------------------------------
            //Register Xoodyak's inputs.  Instantiates the state.  
            //----------------------------------------------------------------
  
          logic [191:0]     textin_r;  //Either plain text or cipher text depending on opmode
          logic [127:0]     key_r,nonce_r;
          logic [351:0]     absdata_r, input_data_r, input_data_trial;
          logic [383:0]     state_cyclist;
          logic [127:0]     ex_hash;
        


          rregs_en #(352) idata_1 (input_data_r,         input_data, eph1, sm_idle_next|reset);    
          rregs_en #(5)   opmd_1  (opmode_r,             reset? '0: opmode             , eph1, sm_idle_next|initial_state|reset);

          assign textin_r = input_data_r[351:160];
          assign nonce_r  = input_data_r[351:224];           
          assign key_r    = input_data_r[351:224];
          assign absdata_r = input_data_r; 

          assign ex_hash = {127{hash_mode}};        
          assign state_cyclist = {key_r&~ex_hash[127:0],15'h0, ~hash_mode, 238'h0, ~hash_mode, 1'h0};
          //assign state_cyclist = {key_r,8'h0, 8'h01, 232'h0, 8'h2}; <- keyed mode only.
          // So the arguments are {key, mod256(id) which is zero, 8'h01, a bunch of zeros, end with 8'h2
 
        
            
          //----------------------------------------------------------------
          //Permute Inputs 
          //----------------------------------------------------------------        
            
          logic [383:0] permute_in, permute_out, absorb_out , state, permin_cd_added, permin, sqz_down, down_out,crypt_down;            
          logic hash_abs_exception, sqz_exception;
   
          rregs_en #(384,MUX) statereg_3 (state, down_out, eph1, reset|(op_switch_next&run)); 
                    
          //Created as a means to catch the state for use after a squeeze function.  
          logic [383:0] saved_squeeze;
          rregs_en #(384,MUX) hack_4 (saved_squeeze, reset? '0: state, eph1, reset|(sm_idle&(sm_sqz_next|sm_sky_next))); 
                 

          assign hash_abs_exception =  sm_abs_next&hash_mode&shadow_abs&meta_cyc;
          assign sqz_exception = ~sm_idle&((shadow_sqz&~sm_sqz) |(~sm_sky&shadow_sky));
          
          rmuxd4_im #(384) exceptionhandler (permin, 
            initial_state                            ,'0,   //First state after reset  Exception handler will require a call to cyclist before you can initialize even in hash mode.  
            hash_abs_exception                       ,{absdata_r[351:224], 8'h1,  248'h1}, //absorbing data after initialization in hash mode (necessary because  state is up)
            sqz_exception                            , saved_squeeze,   //requires the previous state value since the last permute does not affect the state.  
            state
          );
                                        
         ///Adds the Cu value for functions, if applicable. Not applicable if the same function is called more than once in a row (shadow_state==sm_state).  
         //So the shadow state issue creates a problem if you immediately try to decrypt after encrypt or vice versa.  
         /*
         Cu values:
         80 for crypt/decrypt
         40 for squeeze 
         20 for squeeze key
         10 for ratchet, as supplied to modifications to the up function.           
         */
         logic [7:0] cu;
         assign  cu[7]   = ((sm_enc_next|sm_enc) & ~shadow_enc) |((sm_dec_next|sm_dec) & ~shadow_dec);
         assign  cu[6]   = ~shadow_sqz&(sm_sqz_next|sm_sqz)&keyed_mode;
         assign  cu[5]   =  ~shadow_sky&(sm_sky_next|sm_sky) ;
         assign  cu[4]   =  (sm_rat_next|sm_rat);
         assign  cu[3:0] =   4'h0; 
     
         assign permin_cd_added =  {permin[383:8], permin[7:0]^cu};    

        
            //----------------------------------------------------------------
            //Xoodyak Permute --- Instantiates the permute module 
            //----------------------------------------------------------------                
          

          permute #(PERM_INIT, MUX) xoopermute(
              .eph1          (eph1),
              .reset         (reset),
              .run           (permute_run_next),
              .state_in      (permin_cd_added),
              .sbox_ctrl     (perm_ctr),
              .state_out     (permute_out) //permute_out is the nonregistered output of the round.  This is necessary to allow the down function to compute on the same clock
          );    
              
            
              
            //----------------------------------------------------------------
            //Permute post processing --- Modifies the permute output for recyclying through the down() function and associated logic.   
            //This logic occurs in time during the last clock of permute activity, technically after permute (continuous time) but during the same clock.
            //----------------------------------------------------------------          
          
  
          logic [383:0] abs_down_modifier, abs_keyed, abs_hash, abs_non, down_input;
          logic [191:0] ex_rat, ex_dec;

          assign ex_dec  = {192{sm_dec}};
          assign ex_rat  = {128{sm_rat}}; 

          //Calculates results of the Down() function based on the function called; nonce, absorb(keyed), or absorb(hash) respectively. 
          assign abs_non =   {nonce_r, 8'h1,  222'h0, 24'h0, ~shadow_non, ~shadow_non};
          assign abs_keyed = {absdata_r[351:224], absdata_r[223:217], absdata_r[216], absdata_r[215:0], 8'h1, 16'h0, 6'h0, ~shadow_abs, ~shadow_abs};
          assign abs_hash =  {absdata_r[351:224], 8'h1, 247'h0, ~shadow_abs};  //The constant is actually 0x01, will fix before build.  Somehow software doesnt catch this - uses 0x00 for all....
                                                                               //Also the software doesn't recognize the down() function
          
          
          //Selects which form of Down() modification is selected to be applied to the state.   
          rmuxd4_im #(384) absot (abs_down_modifier,
                        sm_non                 ,abs_non,
                        sm_abs&keyed_mode      ,abs_keyed, 
                        sm_abs&hash_mode       ,abs_hash,
                        384'h0
          ); 
              
          //For one clock functions the state, subject to the exception handler, is applied to the down function.
          //These are the "one clock functions"            
          assign down_input =  one_clock_functions ? permin : permute_out;


          //Calculates the outputs of the down functions, depending on whether it is an absorb, crypt, or squeeze architype.  
          assign absorb_out = abs_down_modifier^down_input;
          assign crypt_down = { textin_r^(down_input[383:192]&~ex_dec),   down_input[191:185] , ~down_input[184], down_input[183:0] };     
          assign sqz_down[383:256] = {down_input[383:377], down_input[376]^(sm_sqz), down_input[375:256]}&~ex_rat;
          assign sqz_down[255:0]   = {down_input[255:249], down_input[248]^(~sm_sqz), down_input[247:0]};   
                                                                                            

          rmuxdx4_im #(384) downsel   (down_out, 
                
                 reset | sm_cyc                       ,state_cyclist,
                ~reset & sm_abs | sm_non              , absorb_out,   
                ~reset & sm_enc | sm_dec              , crypt_down,               
                ~reset & sm_sqz | sm_rat | sm_sky     , sqz_down

           );                                                          

         //----------------------------------------------------------------
         //Selecting the output text. 
         //----------------------------------------------------------------         
      
        //This mux selects the output text depending on the previous function call.  The outputs are zeros unless the function generates a real output. 
           logic [191:0] textout_sel;
        
           rmuxd4_im #(192) txtut (  textout_sel ,
              sm_enc                      ,down_out[383:192],
              sm_dec                      ,textin_r^permute_out[383:192],
              (sm_sqz|sm_sky)             ,{down_out[383:377], down_out[376]^sm_sqz, down_out[375:256],{64{1'b0}}},
              '0
           );   


        endmodule: xoodyak_build   
        
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////      
        

 
 ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 
     
      module permute #(parameter PERM_INIT=3, parameter MUX = 1)( 
      
          input logic          eph1,
          input logic          reset, 
           
          input logic          run,  //No serious start condition here, this only allows the output to turn over, which should happen whenever the output is ready.  
          input logic  [383:0] state_in,  //Indicies: plane, lane, zed
          input logic  [2:0]   sbox_ctrl, 
          
          output logic [383:0] state_out

      );
          //----------------------------------------------------------------
          //XOODYAK's permute function
          //----------------------------------------------------------------
          /*
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
        

      logic  [383:0] state_interm;      
      logic [3:0][11:0] SBOX0, SBOX1, SBOX2;
      assign SBOX0 = { 12'h58 ,  12'hd0 ,  12'h60 , 12'hf0   }; 
      assign SBOX1 = { 12'h38 ,  12'h120,  12'h2c , 12'h1a0  };      
      assign SBOX2 = { 12'h3c0,  12'h14 ,  12'h380, 12'h12   };  


  
      logic [11:0] sbox_rnd0, sbox_rnd1, sbox_rnd2, sbox_rnd3;
      assign sbox_rnd0 = SBOX0[sbox_ctrl];
      assign sbox_rnd1 = SBOX1[sbox_ctrl];
      assign sbox_rnd2 = SBOX2[sbox_ctrl]; 
      
        //Greek syms.  θ ρwest ι Χ ρeast
        //The CIBOX constants, retained for reference, are: '{ 32'h58, 32'h38, 32'h3c0, 32'hD0, 32'h120, 32'h14, 32'h60, 32'h2c, 32'h380, 32'hF0, 32'h1A0, 32'h12}; 
       
        logic [383:0]  bits_le, state_recycle, permin;
        assign bits_le = {// So not only is each block of 32' reversed in a 128' double double word, but each 
                          //128' double double word position is reversed in the total state. 
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
    
     assign permin = (sbox_ctrl == PERM_INIT) ? bits_le : state_recycle;  
      
      permute_rnd perm3( 
      
          .rc0  (sbox_rnd0),
          .rc1  (sbox_rnd1),
          .rc2  (sbox_rnd2),
          .state_in  (permin),
          
          .state_out (state_interm)

      );
      
      rregs_en #(384,MUX) permstate_6 (state_recycle, reset ? '0 : state_interm, eph1, reset|run);      
    

      assign state_out = {      state_interm[103:96] ,state_interm[111:104],state_interm[119:112],state_interm[127:120],
                                state_interm[71:64]  ,state_interm[79:72]  ,state_interm[87:80]  ,state_interm[95:88],
                                state_interm[39:32]  ,state_interm[47:40]  ,state_interm[55:48]  ,state_interm[63:56],
                                state_interm[7:0]    ,state_interm[15:8]   ,state_interm[23:16]  ,state_interm[31:24],                          
                                
                                state_interm[231:224],state_interm[239:232],state_interm[247:240],state_interm[255:248],
                                state_interm[199:192],state_interm[207:200],state_interm[215:208],state_interm[223:216],
                                state_interm[167:160],state_interm[175:168],state_interm[183:176],state_interm[191:184],
                                state_interm[135:128],state_interm[143:136],state_interm[151:144],state_interm[159:152],
                                
                                state_interm[359:352],state_interm[367:360],state_interm[375:368], state_interm[383:376],
                                state_interm[327:320],state_interm[335:328],state_interm[343:336],state_interm[351:344],
                                state_interm[295:288],state_interm[303:296],state_interm[311:304],state_interm[319:312],
                                state_interm[263:256],state_interm[271:264],state_interm[279:272],state_interm[287:280]
                              }; 
     
     
       endmodule: permute
 
 
 
 
       module permute_rnd( 
      
         
          input logic [11:0]    rc0,
          input logic [11:0]    rc1,
          input logic [11:0]    rc2,       
          
          input logic  [383:0]  state_in,  //Indicies: plane, lane, zed
          
          output logic [383:0] state_out

      );
                 

        
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////Round zero///////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        //θ 
        
        logic [3:0][31:0] p_0, e_0; //Indicies: lane, zed.
        logic [2:0][3:0][31:0] perm_input_0;

        assign perm_input_0 = state_in;
        
        // P <- A0 + A1 + A2
        assign p_0 =  perm_input_0[0]^perm_input_0[1]^perm_input_0[2]; 

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

assign rho_west_0[0][3][31:12]= theta_out_0[0][3][31:12];
assign rho_west_0[0][3][11:0] = theta_out_0[0][3][11:0] ^ rc0; 
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
        // Ay <- Ay^By for y{0,1,2}
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




assign rho_west_1[0][3][31:12]= theta_out_1[0][3][31:12];
assign rho_west_1[0][3][11:0] = theta_out_1[0][3][11:0] ^ rc1;  
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


assign rho_west_2[0][3][31:12]= theta_out_2[0][3][31:12];
assign rho_west_2[0][3][11:0] = theta_out_2[0][3][11:0] ^ rc2; 
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

        
        assign state_out = rho_east_2;

      endmodule: permute_rnd
