    module permute( //Maybe I should be registering at the end of every instance of round for timing. 
    //Per the xoodoo cookbook, array indices are (z+32*(x+4y)), where y is the plane, x is the lane, and z is the depth of the lane. 

      input logic         eph1,
      input logic          reset, 
      input logic         start,  //start has to be a pulse.  
      input logic  [383:0] state_in,  //Indicies: plane, lane, zed
      
      output logic [383:0] state_out,
      output logic xood_done 

    );

    //Lookup table Fake for now.  There doesn't appear to be a functional difference between 128' and, 2+4+4 = 10 bits here...
    const logic [12:1][127:0] CIBOX = '{ 32'h58, 32'h38, 32'h3c0, 32'hD0, 32'h120, 32'h14, 
    32'h60, 32'h2c, 32'h380, 32'hF0, 32'h1A0, 32'h12}; //May need to revese

    logic [3:0] rnd_cnt, rnd_cnt_next;
    //fake counter, will be replaced by direct evaluation.  
      
    
    assign rnd_cnt_next = rnd_cnt - 1;  
    
    rregs #(4) xooctr (rnd_cnt, start? 4'hc : rnd_cnt_next ,eph1);
    //assign rnd_cnt = start ? 4'hc : rnd_cnt_next; //Get the feeling I'm going to be off by one round here.
    assign xood_done = (rnd_cnt == 4'h1);
    
    logic [2:0][3:0][31:0] rnd_recycle; 
    logic [383:0] bits_in, bits_le;
    logic [2:0][3:0][31:0] perm_in ; //Indicies: plane, lane, zed
    //Traditioanl formatting: assign perm_in = state_in;
        assign bits_in = (rnd_cnt == 12) ? state_in : rnd_recycle; 
    assign bits_le = {
											bits_in[103:96] ,bits_in[111:104],bits_in[119:112],bits_in[127:120],
                      bits_in[71:64]  ,bits_in[79:72]  ,bits_in[87:80]  ,bits_in[95:88],
                      bits_in[39:32]  ,bits_in[47:40]  ,bits_in[55:48]  ,bits_in[63:56],
                      bits_in[7:0]    ,bits_in[15:8]   ,bits_in[23:16]  ,bits_in[31:24],
											
                      bits_in[231:224],bits_in[239:232],bits_in[247:240],bits_in[255:248],
                      bits_in[199:192],bits_in[207:200],bits_in[215:208],bits_in[223:216],
                      bits_in[167:160],bits_in[175:168],bits_in[183:176],bits_in[191:184],
                      bits_in[135:128],bits_in[143:136],bits_in[151:144],bits_in[159:152],
											
											bits_in[359:352], bits_in[367:360], bits_in[375:368], bits_in[383:376],
                      bits_in[327:320],bits_in[335:328],bits_in[343:336],bits_in[351:344],
                      bits_in[295:288],bits_in[303:296],bits_in[311:304],bits_in[319:312],
                      bits_in[263:256],bits_in[271:264],bits_in[279:272],bits_in[287:280]
											

											};

    //Round zero

    //Theta input
    logic [3:0][31:0] p, e; //Indicies: lane, zed.
    logic [2:0][3:0][31:0] rnd_input;

    assign rnd_input = (rnd_cnt == 12) ? bits_le : rnd_recycle;
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
      
      assign const_wire = CIBOX[rnd_cnt];
      
      //The python script definitely doesn't lookup anything except the first set
      //Per the tech standard, it should be modifiying rho_west[0][0] instead but endianness is getting in the way.  
      assign rho_west[2][3] = theta_out[2][3]; //^ CIBOX[rnd_cnt]
      assign rho_west[2][2] = theta_out[2][2]; 
      assign rho_west[2][1] = theta_out[2][1]; 
      assign rho_west[2][0] = theta_out[2][0] ^ CIBOX[rnd_cnt]; 
      

    logic [2:0][3:0][31:0] chi_out;

    assign chi_out[2] = rho_west[2]^(~rho_west[1]&rho_west[0]);
    assign chi_out[1] = rho_west[1]^(~rho_west[0]&rho_west[2]);
    assign chi_out[0] = rho_west[0]^(~rho_west[2]&rho_west[1]);
    
    //Rho_east
    logic [2:0][3:0][31:0] rho_east;

    //Having rho_east oriented this way allows it to match up with the software, but 
    //technically the second plane should be undergoing these manipulations, 
    //so both the rho east and chi_out are flipped across the plane [1] axis.  
    assign rho_east[2][3] = {chi_out[2][1][23:0], chi_out[2][1][31:24]};
    assign rho_east[2][2] = {chi_out[2][0][23:0], chi_out[2][0][31:24]};
    assign rho_east[2][1] = {chi_out[2][3][23:0], chi_out[2][3][31:24]};
    assign rho_east[2][0] = {chi_out[2][2][23:0], chi_out[2][2][31:24]};

    assign rho_east[1][3] = {chi_out[1][3][30:0], chi_out[1][3][31]};  
    assign rho_east[1][2] = {chi_out[1][2][30:0], chi_out[1][2][31]};
    assign rho_east[1][1] = {chi_out[1][1][30:0], chi_out[1][1][31]};
    assign rho_east[1][0] = {chi_out[1][0][30:0], chi_out[1][0][31]};
   
   assign rho_east[0] = chi_out[0];

    logic [383:0] round_out;
    
    assign round_out = rho_east;

    
    rregs  #(384) rndwire (rnd_recycle ,round_out,eph1);
    logic [11:0][31:0] state_wiretap;
    assign state_wiretap = round_out;

    //Rotate the state to get it to comply with the C code again for the output:  
    
    assign state_out = { round_out[103:96] ,round_out[111:104],round_out[119:112],round_out[127:120],
                  round_out[71:64]  ,round_out[79:72]  ,round_out[87:80]  ,round_out[95:88],
                  round_out[39:32]  ,round_out[47:40]  ,round_out[55:48]  ,round_out[63:56],
                  round_out[7:0]    ,round_out[15:8]   ,round_out[23:16]  ,round_out[31:24],
									
									
									
                  round_out[231:224],round_out[239:232],round_out[247:240],round_out[255:248],
                  round_out[199:192],round_out[207:200],round_out[215:208],round_out[223:216],
                  round_out[167:160],round_out[175:168],round_out[183:176],round_out[191:184],
                  round_out[135:128],round_out[143:136],round_out[151:144],round_out[159:152],
									
									
									

									
									round_out[359:352], round_out[367:360], round_out[375:368], round_out[383:376],
                  round_out[327:320],round_out[335:328],round_out[343:336],round_out[351:344],
                  round_out[295:288],round_out[303:296],round_out[311:304],round_out[319:312],
                  round_out[263:256],round_out[271:264],round_out[279:272],round_out[287:280]
									};

    endmodule: permute
