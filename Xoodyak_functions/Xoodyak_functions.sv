/*Weird comments:

1.  Calls to the squeeze function set the state "up" but never "down." Does this cause a deadlock, algorithmically speaking?
2.  The user isn't prevented from making illogical function calls (keyed calls in hash mode etc)
3.  Can now support any length hashes in hash mode but the user is required to tell me via opmode if there is more hash required afterwards.  
4.  Changing the mux output to be default cyclist output means that the user can screw himself by not assertingproper opcodes at all times. 
    whereas before 

Tested functions:
All functions are operational. 



Test vectors run:
Hash initialize -> absorb -> absorb -> squeeze -> squeeze
Keyed initialize -> nonce -> absorb -> absorb -> crypt -> crypt -> squeeze(keyed mode) 
keyed initialize -> nonce -> absorb -> absorb -> squeezekey()


Still need to:
1. Run more test vectors, revalidate hash functions.
2. Inspect timing related issues.
3. Remove X possiblities from muxes and registers.  
4. See if I can consolidate user's opcode vector. 
5. Check if I can successfully call functions after squeeze/the function is still in an up() state.  
6. Check for instability that changing user inputs can cause.  Certain "hash more" functionalities come to mind. 



*/      


      module xoodyak_build(
          input logic             eph1,
          input logic             reset,
          
          input logic [351:0]     input_data, 
          input logic [5:0]       opmode,    

          output logic [191:0]    textout,
          output logic            finished
          
        );
        
        //Parameter definitions are on line 128 and 129.

 
           
           
                //----------------------------------------------------------------
                //Technical briefing on XOODYAK
                //----------------------------------------------------------------                
          /*    
           Important information:
     
           
           Xoodyak requires:

            
            Xoodyak produces:
                 
           */ 
      
            //----------------------------------------------------------------
            //XOODYAK's governing Finite State Machine  
            //----------------------------------------------------------------
        logic                    sm_idle,  sm_cyc, sm_run, sm_idle_next, sm_run_next, sm_cyc_next,  sm_non_next, op_switch_next,
                                 sm_abs_next , sm_abs , sm_enc_next, sm_enc, sm_sqz_next, sm_sqz, sm_finish_next, run, sm_non, sm_dec_next, sm_dec,
                                 sm_rat, sm_rat_next, sm_sky, sm_sky_next, sm_hsq, sm_hsq_next, hash_mode, keyed_mode, sqz_more, initial_state, one_clock_functions; 
        logic   [127:0]          plain_text_r, round_recycle;
        logic   [3:0]            cycle_ctr_pr, cycle_ctr;
        
        
        assign run =  sm_cyc | sm_non | sm_abs | sm_enc  | sm_dec | sm_sqz | sm_sky | sm_rat;
        assign run_next = sm_cyc_next | sm_non_next | sm_abs_next | sm_enc_next  | sm_dec_next | sm_sqz_next | sm_rat_next | sm_sky_next; //sm_non;
        assign initial_state = ~(shadow_cyc|shadow_non|shadow_abs|shadow_enc|shadow_dec|shadow_sqz|shadow_rat|shadow_sky);
        assign one_clock_functions = sm_cyc | (~sm_sqz&shadow_sqz) | (sm_abs&hash_mode&~shadow_abs&shadow_cyc);
        
        //FSM

       assign sm_idle_next      = (sm_idle & (~run_next) | (op_switch_next & run) | sm_cyc);
       assign sm_cyc_next       = (sm_idle & (opmode[3:0] == 4'b0001)) ;        
       assign sm_non_next       = (sm_idle & (opmode[3:0] == 4'b0010) & keyed_mode) | (sm_non   &  ~op_switch_next); 
       assign sm_abs_next       = (sm_idle & (opmode[3:0] == 4'b0011)             ) | (sm_abs  &  ~op_switch_next); // Not Keymode only
       assign sm_enc_next       = (sm_idle & (opmode[3:0] == 4'b0100) & keyed_mode) | (sm_enc   &  ~op_switch_next);
       assign sm_dec_next       = (sm_idle & (opmode[3:0] == 4'b0101) & keyed_mode) | (sm_dec   &  ~op_switch_next); 
       assign sm_sqz_next       = (sm_idle & (opmode[3:0] == 4'b0110)             ) | (sm_sqz   &  ~op_switch_next);   //Not keyed mode only.
       assign sm_rat_next       = (sm_idle & (opmode[3:0] == 4'b0111) & keyed_mode) | (sm_rat   &  ~op_switch_next); 
       assign sm_sky_next       = (sm_idle & (opmode[3:0] == 4'b1000) & keyed_mode) | (sm_sky   &  ~op_switch_next); 
                                  //I removed the _r component from opmode for timing purposes.  I also think this is valid since the user should be able to change
                                  //at any point prior to the clock cycle.  GH please advise.  
                                  
                                  
       assign sqz_more =    (opmode_r[4:0]==5'b10110);  //Hash_more says that the user wants at least 128' more data than the existing hash.  
       assign hash_mode =   opmode_r[5];
       assign keyed_mode = ~opmode_r[5];
       
       
       
        
        rregs #(1) smir (sm_idle,    reset | sm_idle_next,   eph1);
        rregs #(1) smsr (sm_cyc,    ~reset & sm_cyc_next,    eph1);
        rregs #(1) smno (sm_non,    ~reset & sm_non_next,    eph1); //Commented when in Gimmick mode.  
        rregs #(1) smas (sm_abs,    ~reset & sm_abs_next,    eph1);
        rregs #(1) smen (sm_enc,    ~reset & sm_enc_next,    eph1);
        rregs #(1) smde (sm_dec,    ~reset & sm_dec_next,    eph1);        
        rregs #(1) smsq (sm_sqz,    ~reset & sm_sqz_next,    eph1);
        rregs #(1) smra (sm_rat,    ~reset & sm_rat_next,    eph1);
        rregs #(1) smsk (sm_sky,    ~reset & sm_sky_next,    eph1);       
       
        //The shadow state is active for certain states if they were the most recent function called before the previous one.
        //This is important for selecting the input to the next permute.  
        //A shadow state begins on the first idle clock, which is the previous state, and persists until the next function call.
        //When the same function is called multiple times in a row, the shadow state doesn't change.
        
        logic shadow_cyc, shadow_non, shadow_abs, shadow_enc, shadow_dec, shadow_sqz, shadow_rat, shadow_sky ;  

          rregs_en #(1,1) shdwcyc (shadow_cyc , ~reset&sm_cyc      , eph1,  reset|((op_switch_next|sm_cyc)&~sm_idle));
          rregs_en #(1,1) shdwnon (shadow_non , ~reset&sm_non      , eph1,  reset|(op_switch_next&~sm_idle));
          rregs_en #(1,1) shdwabs (shadow_abs , ~reset&sm_abs      , eph1,  reset|(op_switch_next&~sm_idle));     
          rregs_en #(1,1) shdwenc (shadow_enc , ~reset&sm_enc      , eph1,  reset|(op_switch_next&~sm_idle));     
          rregs_en #(1,1) shdwdec (shadow_dec , ~reset&sm_dec      , eph1,  reset|(op_switch_next&~sm_idle));            
          rregs_en #(1,1) shdwsqz (shadow_sqz , ~reset&sm_sqz      , eph1,  reset|(op_switch_next&~sm_idle));
          rregs_en #(1,1) shdwsky (shadow_sky , ~reset&sm_sky      , eph1,  reset|(op_switch_next&~sm_idle));
          rregs_en #(1,1) shdwrat (shadow_rat , ~reset&sm_rat      , eph1,  reset|(op_switch_next&~sm_idle));        
          
         

            
          //The meta state is the function that was selected two function calls ago. That is to say, the function
          //before the one that just completed.    This is important for calculating CD values in certain areas.        
          logic meta_cyc, meta_non, meta_abs, meta_enc, meta_dec, meta_sqz, meta_rat, meta_sky ;  

          rregs_en #(1,1) metacyc (meta_cyc , ~reset&shadow_cyc      , eph1,  reset|((op_switch_next|sm_cyc)&~sm_idle));
          rregs_en #(1,1) metanon (meta_non , ~reset&shadow_non      , eph1,  reset|(op_switch_next&~sm_idle));
          rregs_en #(1,1) metaabs (meta_abs , ~reset&shadow_abs      , eph1,  reset|(op_switch_next&~sm_idle));     
          rregs_en #(1,1) metaenc (meta_enc , ~reset&shadow_enc      , eph1,  reset|(op_switch_next&~sm_idle));     
          rregs_en #(1,1) metadec (meta_dec , ~reset&shadow_dec      , eph1,  reset|(op_switch_next&~sm_idle));            
          rregs_en #(1,1) metasqz (meta_sqz , ~reset&shadow_sqz      , eph1,  reset|(op_switch_next&~sm_idle));
          rregs_en #(1,1) metasky (meta_sky , ~reset&shadow_sky      , eph1,  reset|(op_switch_next&~sm_idle));
          rregs_en #(1,1) metarat (meta_rat , ~reset&shadow_rat      , eph1,  reset|(op_switch_next&~sm_idle));  
  
    
        logic statechange; 
        assign statechange = sm_idle&(sm_non_next | sm_abs_next | sm_enc_next | sm_dec_next | sm_sqz_next | sm_sky_next | sm_rat_next); //sets the perm counter to three whenever there's a state change on the next clock. 
        
   
            //----------------------------------------------------------------
            //State Counters.  Counts how many clocks remain before a state change. 
            //----------------------------------------------------------------   
          
          logic [2:0] perm_ctr,  perm_ctr_next;      

          parameter logic [2:0] PERM_INIT = 3'h3;   
          assign op_switch_next = (perm_ctr == 3'h0);

          assign perm_ctr_next = perm_ctr - 1; 
                    
          rregs_en #(3,1) permc (perm_ctr, (reset | statechange ) ? PERM_INIT : perm_ctr_next, eph1, run_next|reset);  


            //----------------------------------------------------------------
            //Output flags. Synchronizes outputs for sqzdone and encdone.  
            //----------------------------------------------------------------  
            
            assign finished = ~reset&sm_idle; 

            //----------------------------------------------------------------
            //Register Xoodyak's inputs. 
            //----------------------------------------------------------------
  
          logic [191:0]     textin_r;  //Either plain text or cipher text depending on opmode
          logic [127:0]     key_r,nonce_r;
          logic [351:0]     absdata_r, input_data_r, input_data_ri;
          logic [5:0]       opmode_r; 
        

          rregs_en #(352,1) txtr1  ( input_data_ri           , input_data             , eph1, sm_idle);   
          rregs #(352) txtr2  ( input_data_r           , input_data_ri             , eph1);         

            assign textin_r = input_data_r[351:160];
          assign nonce_r  = input_data_r[351:224];           
          assign key_r    = input_data_r[351:224];
          assign absdata_r = input_data_r; 
          rregs_en #(6,1)   opmd  (opmode_r                , opmode             , eph1, sm_idle);



        logic [383:0] state_cyclist;
        logic [215:0] ex_hash;
        assign ex_hash = {216{hash_mode}};
        
        assign state_cyclist = {key_r&~ex_hash[127:0],15'h0, ~hash_mode, 238'h0, ~hash_mode, 1'h0};
        //assign state_cyclist = {key_r,8'h0, 8'h01, 232'h0, 8'h2}; <- keyed mode only.
        // So the arguments are {key, mod256(id) which is zero, 8'h01, a bunch of zeros, end with 8'h2
 
        
            
            //----------------------------------------------------------------
            //Permute Inputs 
            //----------------------------------------------------------------        
            
        logic [383:0] permute_in, permute_out, absorb_out , nonce_out, func_outputs, permin_cd_added, saved_state, sqz_down, rat_state;
        logic perm_done, start_flags;             
             logic [383:0] crypt_down, decout;   

       
        //This mux isn't permin any more, it's the end of a round state.  
        //Obviously there should never be able to satisfy multiple states....
        //If I change the selector pins to the shadow state I don't think I'll have to use a register to store the state since only one 
        //shadow state should be active at a time. 
        
       rmuxdx4_im #(384) permin1   (func_outputs, 
              
              shadow_cyc                           ,state_cyclist,
              shadow_abs | shadow_non              , absorb_out,   
              shadow_enc | shadow_dec              , crypt_down,  //crypt input.                
              shadow_sqz | shadow_rat | shadow_sky , sqz_down
              //                                       state_cyclist
        ); 
        
        
        logic [383:0] saved_squeeze;
        rregs_en #(384,1) sqzrecovery (saved_squeeze, saved_state, eph1, sm_idle); 
        
        rmuxd4_im #(384) exceptionhandler (saved_state, 
          initial_state                            ,'0,   //First state after reset  Exception handler will require a call to cyclist before you can initialize even in hash mode.  
          sm_abs&hash_mode&~shadow_abs&shadow_cyc ,{absdata_r[351:224], 8'h1,  248'h1}, //absorbing data after initialization in hash mode (necessary because  state is up)
          shadow_sqz&~sm_sqz                      , saved_squeeze,   //requires the previous state value since the last permute does not affect the state.  
          func_outputs
        );
        

        
        //The no kidding text output, doesn't need to be registered since there's only one gate inbetween that and the output text.  
      logic [191:0] ex_encdone, ex_sqzdone, ex_decdone, ex_skydone, ex_rat;


      assign ex_encdone = {128{shadow_enc}};  //abs was here?
      assign ex_sqzdone = {128{shadow_sqz}};   // nonce waas here?
      assign ex_decdone = {128{shadow_dec}};
      assign ex_skydone = {128{shadow_sky}};
      assign ex_rat     = {128{shadow_rat}};
      

    
    rmuxd4_im #(192) txtut (  textout ,
            sm_idle&shadow_enc,       saved_state[383:192],
            sm_idle&shadow_dec,        textin_r^permute_out[383:192],
            sm_idle&shadow_sqz,       {permute_out[383:256],{64{1'b0}}},
            '0);                              
    
    

        
         ///Adds the Cd value for crypt functions, if applicable. Not applicable if multiple crypt or decyrpt functions in a row.  
         //So the shadow state issue creates a problem if you immediately try to decrypt after encrypt or vice versa.  
         logic [7:0] cd;
         assign cd = { ((sm_enc_next|sm_enc) & ~shadow_enc) |((sm_dec_next|sm_dec) & ~shadow_dec), ((sm_sqz_next|sm_sqz)&keyed_mode), (sm_sky_next|sm_sky) , (sm_rat_next|sm_rat), 4'h0};
                                                                                                                          // 0 in hash mode. 
     
        assign permin_cd_added =  {saved_state[383:8], saved_state[7:0]^cd};    

        logic permute_running_wire;
         assign permute_running_wire =      ~(sm_idle|one_clock_functions);  
        
            //----------------------------------------------------------------
            //Xoodyak Permute --- Instantiates the permute module 
            //----------------------------------------------------------------                
          
          permute #(PERM_INIT) xoopermute(
              .eph1          (eph1),
              .reset         (reset),
              .run           (~(sm_idle|one_clock_functions)),
              .state_in      (permin_cd_added),
              .sbox_ctrl     (perm_ctr),
              .state_out     (permute_out)
          );    
              
            //----------------------------------------------------------------
            //Permute post processing --- Modifies the permute output for recyclying.             
            //----------------------------------------------------------------          
          
          //This performs the absorb manipulation required on the permute output:
          //For DOWN(extra_data,8'h03)
       
 

          // perm_out ^ (Xi||8'h01||'00(extended)||Cd)  Cd is 8'h03.  
    
  
        logic [383:0] abs_down_modifier, absorb_out2, abs_keyed, abs_hash, abs_non, down_input;
        
        assign down_input =  (sm_cyc | (~sm_sqz&shadow_sqz)) ? saved_state : permute_out;
        assign abs_non =   {nonce_r, 8'h1,  222'h0, 24'h0, ~meta_non, ~meta_non};
        assign abs_keyed = {absdata_r[351:224], absdata_r[223:217], absdata_r[216], absdata_r[215:0], 8'h1, 16'h0, 6'h0, ~meta_abs, ~meta_abs};
        assign abs_hash =  {absdata_r[351:224], 8'h1, 248'h0};
        
        
        //To replace the absorb_out rats nest.  
        rmuxd4_im #(384) absot (abs_down_modifier,
                      shadow_non                 ,abs_non,
                      shadow_abs&keyed_mode       ,abs_keyed, 
                      shadow_abs&hash_mode       ,abs_hash,
                      384'h0
        ); 
        

         assign absorb_out = abs_down_modifier^down_input;
        //////////////////////
      
          logic[191:0] ex_shdw_dec;
          assign ex_shdw_dec = {192{shadow_dec}};
          
          
           assign crypt_down = { textin_r^(down_input[383:192]&~ex_shdw_dec),   down_input[191:185] , ~down_input[184], down_input[183:0] };
//                                                                                              ^^^^ This term was conspicuously absent ('01'), but clearly algoirthmically required.  
           
        
        assign sqz_down[384:256] = {down_input[383:377], down_input[376]^(sqz_more), down_input[375:256]}&~ex_rat; //Instability in sqz_more 
        assign sqz_down[255:0]   = {down_input[255:249], down_input[248]^(~shadow_sqz), down_input[247:0]};         
                                                           //~down_input[248]           


        endmodule: xoodyak_build   
        
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////      
        

 
 ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 
     
      module permute #(parameter PERM_INIT=3)( 
      
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
      
      rregs_en #(384,1) permstate (state_recycle, reset ? '0 : state_interm, eph1, reset|run);      
    

      assign state_out = {      state_recycle[103:96] ,state_recycle[111:104],state_recycle[119:112],state_recycle[127:120],
                                state_recycle[71:64]  ,state_recycle[79:72]  ,state_recycle[87:80]  ,state_recycle[95:88],
                                state_recycle[39:32]  ,state_recycle[47:40]  ,state_recycle[55:48]  ,state_recycle[63:56],
                                state_recycle[7:0]    ,state_recycle[15:8]   ,state_recycle[23:16]  ,state_recycle[31:24],                          
                                
                                state_recycle[231:224],state_recycle[239:232],state_recycle[247:240],state_recycle[255:248],
                                state_recycle[199:192],state_recycle[207:200],state_recycle[215:208],state_recycle[223:216],
                                state_recycle[167:160],state_recycle[175:168],state_recycle[183:176],state_recycle[191:184],
                                state_recycle[135:128],state_recycle[143:136],state_recycle[151:144],state_recycle[159:152],
                                
                                state_recycle[359:352],state_recycle[367:360],state_recycle[375:368], state_recycle[383:376],
                                state_recycle[327:320],state_recycle[335:328],state_recycle[343:336],state_recycle[351:344],
                                state_recycle[295:288],state_recycle[303:296],state_recycle[311:304],state_recycle[319:312],
                                state_recycle[263:256],state_recycle[271:264],state_recycle[279:272],state_recycle[287:280]
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


 
     