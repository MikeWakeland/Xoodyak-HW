/* 
Known design flaws:

There is a dead clock after every function call.

rmuxd4_im #(384) absot's associated inputs for nonce and absorb can be easily consolidated into a signle input pin.  This allows for 
the 4:1 mux to be reduced to 2:1 with the removal of the redundant pin.  

You cannot call the same function twice in a row without it being seen as the same function call.  Perhaps we can add another function call to clear 
the shadow state and allow this to occur?  


*/

/*


AES Encrypt and Decrypt require 11/11/11 clocks per encrypt because the FSM doesn't allow you to kick directly to run after finishing.  Should be single line fix.  

How much effort would it take to create a GCM function for AES? 

*/