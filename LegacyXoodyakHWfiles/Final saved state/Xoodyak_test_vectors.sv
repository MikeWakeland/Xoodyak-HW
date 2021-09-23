	 This  testbench is for cyclist key -> absorb -> absorb -> decrypt -> decrypt 
		
	logic [8:0][351:0] input_data_t; 
	assign plaintext_t = {192'h4d4e4f5051525354555657584142434445464748494a4b4c};
	assign key_t = 128'h38393a3b3c3d3e3f3031323334353637;  //ascii text:  0123456789:;<=>? orig: nonce
	assign nonce_t= 128'h494a4b4c4d4e4f504142434445464748;  //ascii text: ABCDEFGHIJKLMNOP orig: asso_data
	assign asso_data_t = 352'h6162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c; //ascii text: iabcdefghijkiabcdefghijkiabcdefg orig: key
	
	
	//use SOFTWARE text to generate the hex values to run through hardware.  THis is much more robust.  

	logic [191:0] ciphertext;
assign ciphertext	= (opmode_ctr > 21)? 192'h87a06d5561b0d87c20a12db5d34783258ff75fe5d87c0e30 : 192'hbb4416e8d6ce6ef456e2be6c08ce8eccaf42fd7c33b3de1e;
	                                                                                                            
	assign input_data_t = {
	       352'h0,  //sky input
				 352'h0,  //rat input
         352'h0,  //sqz input
         {ciphertext, 160'h0},  //dec input,
         {192'h4d4e4f5051525354555657584142434445464748494a4b4c, 160'h0},
         352'h6162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c, //asso data
 				 {128'h494a4b4c4d4e4f504142434445464748, 224'h0}, //nonce
         {128'h38393a3b3c3d3e3f3031323334353637, 224'h0}, // key/cyclist
				 352'h0};				 //idle 

	
	logic[47:0][5:0] opmode_t;
	assign opmode_t = { 6'h0, 6'h0,
										 6'h1, 6'h1, 6'h1, 6'h1, 6'h1, 6'h1,
										 6'h2, 6'h2, 6'h2, 6'h3, 6'h3, 6'h3,
										 6'h3, 6'h3, 6'h3, 6'h3, 6'h3, 6'h3,
										  6'h5, 6'h5, 6'h5, 
										 6'h5, 6'h5, 6'h5,  6'h5, 6'h5, 6'h5, //10 0f 0e 0d 0c 0b 
							//			 6'h5, 6'h5, 6'h5, 6'h5, 6'h5, 6'h5,  //
										// 6'h6, 6'h6, 6'h6, 6'h6, 6'h6, 6'h6,
										 6'h5, 6'h5, 6'h5, 6'h5, 6'h5, 6'h5,
										 6'h0, 6'h0, 6'h0, 6'h0, 6'h4, 6'h4, 6'h4, 6'h4, 6'h4, 6'h4,
										 6'h4, 6'h4, 6'h4};
										 
										 
										 


 xoocycle_cyclist(&cyc, (CU8P)"89:;<=>?01234567", 16, xoocycle_empty, 0,
                xoocycle_empty, 0); //Remember to change the keysize up in the cyclist function (KEY)


  xoocycle_absorb(&cyc, (CU8P)"IJKLMNOPABCDEFGH", 16);  //(NONCE)
  printf("state after nonce is \n"); //NEWLINE
  print8(&cyc, 48); //NEWLINE



  xoocycle_absorb(&cyc, (CU8P)"abcdefghijklmnopabcdefghijklmnopabcdefghijklabcdefghijklmnopabcdefghijklmnopabcdefghijkl", 88); //(ASSOCIATED DATA) //abcdefghijklmnopabcdefghijklmnopabcdefghijkl
 printf("state after absorbing AD is \n"); //NEWLINE
 print8(&cyc, 48); //NEWLINE


 xoocycle_encrypt(&cyc, plain, PLAIN); //(PLAINTEXT)
  printf("state after ENC is \n"); //NEWLINE
  print8(&cyc, 48);

  xoocycle_squeeze(&cyc, tag, 16);
  print8(&tag, 16);

 
  										 
										 

Software output on this function: 										 
The key in hex is:
38393a3b3c3d3e3f3031323334353637
state before absorption in cyclist is 
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
state after absorption in cyclist is 
38393a3b3c3d3e3f30313233343536370001000000000000000000000000000000000000000000000000000000000002
the absorb input in hex is: 
494a4b4c4d4e4f504142434445464748007374617465206166746572206e6f6e636520697320000061626364
state input to perm is 
38393a3b3c3d3e3f30313233343536370001000000000000000000000000000000000000000000000000000000000002
state out from perm is 
6da9009658a57623a2e65dda5181f626225b9cc9c969dc471d7582c9b4d7b15567f2db147da3d4dd28aaf20e92e436ab
state after nonce is 
24e34bda15eb3973e3a41e9e14c7b16e235b9cc9c969dc471d7582c9b4d7b15567f2db147da3d4dd28aaf20e92e436a8
the absorb input in hex is: 
6162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c
state input to perm is 
24e34bda15eb3973e3a41e9e14c7b16e235b9cc9c969dc471d7582c9b4d7b15567f2db147da3d4dd28aaf20e92e436a8
state out from perm is 
ba9372694bf25e85fff28a560ff56f2a22181a43d9d31d697470d287d82ba4a76bb1d4544f4f5b68e9e1e8ce180eae42
state input to perm is 
dbf1110d2e9439ed9698e13a629b005a437a7927bcb57a011d1ab9ebb545cbd70ad3b7302a293c00808b83a2190eae41
state out from perm is 
01993b3a0b4c820ecb7958a1bc6ee8c6c993f0b805cfcd9925dbd432e8925bf7e0649a51ad281acd0180ab3261a753a8
state after absorbing AD is 
60fb585e6e2ae566a21333cdd10087b6a8f193dc60a9aaf14cb1bf5e85fc34878106f935c84e7da568eac05e60a753a8

Before CRYPTO, the state is: 
60fb585e6e2ae566a21333cdd10087b6a8f193dc60a9aaf14cb1bf5e85fc34878106f935c84e7da568eac05e60a753a8
state input to perm is 
60fb585e6e2ae566a21333cdd10087b6a8f193dc60a9aaf14cb1bf5e85fc34878106f935c84e7da568eac05e60a75328
60fb585e6e2ae566a21333cdd10087b6a8f193dc60a9aaf14cb1bf5e85fc34878106f935c84e7da568eac05e60a75328
state out from perm is 
caee220530e28b2875f77aed9205c061cab118ad9136457c65dfe435e5cafc46cae7d8ad76076bd5d88a9f00a9ce6948
Before Mysterywrite, the state is: 
caee220530e28b2875f77aed9205c061cab118ad9136457c65dfe435e5cafc46cae7d8ad76076bd5d88a9f00a9ce6948
caee220530e28b2875f77aed9205c061cab118ad9136457c
down input is: 
4d4e4f5051525354555657584142434445464748494a4b4c
After Mysterywrite, the state is: 
87a06d5561b0d87c20a12db5d34783258ff75fe5d87c0e30 64dfe435e5cafc46cae7d8ad76076bd5d88a9f00a9ce6948
4d4e4f5051525354555657584142434445464748494a4b4c 64dfe435e5cafc46cae7d8ad76076bd5d88a9f00a9ce6948
state input to perm is 
87a06d5561b0d87c20a12db5d34783258ff75fe5d87c0e3064dfe435e5cafc46cae7d8ad76076bd5d88a9f00a9ce6948
state out from perm is 
f60a59b8879c3da003b4e934498ccd88ea04ba347af995527a770716bbfb29f071d2b662f91763942ea7c4a3fa2542b7
Before Mysterywrite, the state is: 
f60a59b8879c3da003b4e934498ccd88ea04ba347af995527a770716bbfb29f071d2b662f91763942ea7c4a3fa2542b7
down input is: 
4d4e4f5051525354555657584142434445464748494a4b4c
After Mysterywrite, the state is: 
bb4416e8d6ce6ef456e2be6c08ce8eccaf42fd7c33b3de1e7b770716bbfb29f071d2b662f91763942ea7c4a3fa2542b7
state after ENC is 
bb4416e8d6ce6ef456e2be6c08ce8eccaf42fd7c33b3de1e7b770716bbfb29f071d2b662f91763942ea7c4a3fa2542b7
The state before squeeze is: 
bb4416e8d6ce6ef456e2be6c08ce8eccaf42fd7c33b3de1e7b770716bbfb29f071d2b662f91763942ea7c4a3fa2542b7
state input to perm is 
bb4416e8d6ce6ef456e2be6c08ce8eccaf42fd7c33b3de1e7b770716bbfb29f071d2b662f91763942ea7c4a3fa2542f7
bb4416e8d6ce6ef456e2be6c08ce8eccaf42fd7c33b3de1e7b770716bbfb29f071d2b662f91763942ea7c4a3fa254297

state out from perm is 
9dbe0dbab3c16ac63756be78c6a29a234fe4b9ca4605d51622b8726600188c523de45ac04fc33609a39ad4707c5fa508
The state after squeeze is: 
9dbe0dbab3c16ac63756be78c6a29a234fe4b9ca4605d51622b8726600188c523de45ac04fc33609a39ad4707c5fa508
9dbe0dbab3c16ac63756be78c6a29a23									 
										 
										 
	---------------------------------------------------------------------------------------
cyclist -> absorb -> absorb -> absorb -> squeeze -> squeeze 

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

	
	logic[47:0][5:0] opmode_t;
	assign opmode_t = { 5'h20, 5'h20, 5'h20, 5'h20, 5'h20, 5'h20,
										 5'h21, 5'h21, 5'h21, 5'h21, 5'h21, 5'h21,
										 5'h23, 5'h23, 5'h23, 5'h23, 5'h23, 5'h23,
										 5'h23, 5'h23, 5'h23, 5'h36, 5'h36, 5'h36,
										 5'h36, 5'h26, 5'h26, 5'h26, 5'h26, 5'h26,
										 5'h26, 5'h26, 5'h26, 5'h26, 5'h26, 5'h26,
										 5'h26, 5'h26, 5'h26, 5'h26, 5'h24, 5'h24,
										 5'h24, 5'h24, 5'h24, 5'h24, 5'h24, 5'h24
										 }; 




The key in hex is:
00546865207374617465206166746572
state before absorption in cyclist is 
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
the absorb input in hex is: 
6162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c
Domain 0x01 triggers
3
state input to perm is 
6162636465666768696a6b6c6d6e6f700100000000000000000000000000000000000000000000000000000000000001
state out from perm is 
bc5868c1121bb681f08a24d633eec4b6f76d621d12bd00dfe7a2bf5c11bede5f275920b6d47c0e54ae6a9fb3d476509d
Domain 0x01 triggers
0
state input to perm is 
dd3a0ba5777dd1e999e04fba5e80abc6f66d621d12bd00dfe7a2bf5c11bede5f275920b6d47c0e54ae6a9fb3d476509d
dd3a0ba5777dd1e999e04fba5e80abc6f66d621d12bd00dfe7a2bf5c11bede5f275920b6d47c0e54ae6a9fb3d476509d
state out from perm is 
f401f6c2c20d62dd6c0f2524b1b83f425d21b2e2479fbf8c1e3738955305b43333d174ca6951191052200b37eb96214d
Domain 0x01 triggers
0
state after absorbing AD is 
956395a6a76b05b505654e48dcd650325c21b2e2479fbf8c1e3738955305b43333d174ca6951191052200b37eb96214d
The state before squeeze is: 
956395a6a76b05b505654e48dcd650325c21b2e2479fbf8c1e3738955305b43333d174ca6951191052200b37eb96214d
state input to perm is 
956395a6a76b05b505654e48dcd650325c21b2e2479fbf8c1e3738955305b43333d174ca6951191052200b37eb96214d
state out from perm is 
0750f109b97fcfad998fa34bc8342c13543f4f9d94165c96d104988cb9bd6fa00c618f2c5b279b4bcbf0be414cfc4b4f
Domain 0x01 triggers
0
state input to perm is 
0650f109b97fcfad998fa34bc8342c13543f4f9d94165c96d104988cb9bd6fa00c618f2c5b279b4bcbf0be414cfc4b4f
state out from perm is 
bd19bdba3bd3a0d81bdbcbb2cdd5a0ba62e0e1eeb040abd5db8f04450901bd30793e2e875b6650cae4a7b9a5dc226974
The state after squeeze is: 
bd19bdba3bd3a0d81bdbcbb2cdd5a0ba62e0e1eeb040abd5db8f04450901bd30793e2e875b6650cae4a7b9a5dc226974
0750f109b97fcfad998fa34bc8342c13bd19bdba3bd3a0d81bdbcbb2cdd5a0ba


xoocycle_cyclist(&cyc, (CU8P)"", 0, xoocycle_empty, 0,
                  xoocycle_empty, 0); //Remember to change the keysize up in the cyclist function (KEY)


  xoocycle_absorb(&cyc, (CU8P)"abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop",48); //(ASSOCIATED DATA) //abcdefghijklmnopabcdefghijklmnopabcdefghijkl
  printf("state after absorbing AD is \n"); //NEWLINE
  print8(&cyc, 48); //NEWLINE




  xoocycle_squeeze(&cyc, tag2, 32);
  print8(&tag2, 32);
	
		
	
	-----------------------------------------------------------------------
	
	cyclist -> absorb -> absorb -> sqz.  (hash mode) 
	
	
										 	logic[47:0][5:0] opmode_t;
	assign opmode_t = { 6'h00, 6'h10, 6'h10, 6'h10, 6'h10, 6'h10,
										 6'h11, 6'h11, 6'h11, 6'h11, 6'h11, 6'h11,
										 6'h13, 6'h13, 6'h13, 6'h13, 6'h13, 6'h13,
										 6'h13, 6'h13, 6'h13, 6'h36, 6'h36, 6'h36,
										 6'h36, 6'h16, 6'h16, 6'h16, 6'h16, 6'h16,
										 6'h16, 6'h16, 6'h16, 6'h16, 6'h16, 6'h16,
										 6'h16, 6'h16, 6'h16, 6'h16, 6'h14, 6'h14,
										 6'h14, 6'h14, 6'h14, 6'h14, 6'h14, 6'h14
										 }; 
										 
	
	
The key in hex is:
38393a3b3c3d3e3f3031323334353637
state before absorption in cyclist is 
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
state after absorption in cyclist is 
38393a3b3c3d3e3f30313233343536370001000000000000000000000000000000000000000000000000000000000002
the absorb input in hex is: 
6162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c
state input to perm is 
38393a3b3c3d3e3f30313233343536370001000000000000000000000000000000000000000000000000000000000002
state out from perm is 
6da9009658a57623a2e65dda5181f626225b9cc9c969dc471d7582c9b4d7b15567f2db147da3d4dd28aaf20e92e436ab
state input to perm is 
0ccb63f23dc3114bcb8c36b63cef99564339ffadac0fbb2f741fe9a5d9b9de250690b87018c5b3b541c0996293e436a8

state out from perm is 
7a21c4a90ac48575c52ce38db5c94f1c6358a6ea3f90f52d5959ec8297be07ccfef28d5561726217443073aa8b307c4c
state after absorbing AD is 
1b43a7cd6fa2e21dac4688e1d8a7206c023ac58e5af69245303387eefad068bc9f90ee310414057f2d5a18c68a307c4c
The state before squeeze is: 
1b43a7cd6fa2e21dac4688e1d8a7206c023ac58e5af69245303387eefad068bc9f90ee310414057f2d5a18c68a307c4c
state input to perm is 
1b43a7cd6fa2e21dac4688e1d8a7206c023ac58e5af69245303387eefad068bc9f90ee310414057f2d5a18c68a307c6c
state out from perm is 
0ca7d183919fadc3870adb0d0c4ef1c0ea59d58483e56f794a6febacc14284132ee1520d806e98b7a8ede6aadef976aa
The state after squeeze is: 
0ca7d183919fadc3870adb0d0c4ef1c0ea59d58483e56f794a6febacc14284132ee1520d806e98b7a8ede6aadef976aa
The squeez key is
0ca7d183919fadc3870adb0d0c4ef1c0

