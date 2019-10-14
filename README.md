[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
<BR>

<h1>Conceptual Description</h1>
sign_hash - Takes a directory, hashes files and signs them.<br>
check_manifest - Takes manifest and public key from a running of sign_hash and checks to see if manifest was tampered.<br>
check_hash - Takes manifest and public key from a running of sign_hash and looks at a directory to both check to see if the files changed and also checks if manifest was tampered.<br>

<h1>Why Does This Exist<br></h1>
One of the things that always bothered me is that people provide a list of hashes for a series of files. There is no guarantee that the file of hashes were tampered. With this project one can send the file of hashes, named a manifest and if they keep the public key secure, one can check if the manifest has been tampered. The program does not write out a private key on purpose. This prevents someone from tampering with the file after it has been created. As an added security feature, the file uses its length, its hash and signs this hash, making adjusting the file without rehashing and resigning with the private key detectable.<br>

<h1> How To Use <br></h1>
 Use the flag -h for command line flags <br>

`./sign_hash -o manifest234`<br>
 Take current working directory and all sub directories and create a signed hash manifest for them named manifest234
`./check_manifest -i manifest234 -o checkfile234` <br>
 Take manifest234 and check to see if it has been tampered. Write results to file named checkfile234<br>
`./check_hash -i manifest234 -o checkfile234`<br>
 Take current working directory and see if the hashes and files match the files listed in checkfile234. Take manifest234 and check to see if it has been tampered. Write results to file named checkfile234

<h1> Known Issues/Behaviors/Limitations <br></h1>
 Not following symbolic links:<br>
 Program will not follow infinite loops based on hard links (in Linux). Could add a flag to follow symlinks but this could result in a infinite loop so it is not part of the system.<br><br>

Discussion on nonces:<br>
Nonce length is 128 bytes. This means that after 2^64 number of files, there could be a collision. The program ensures that when creating a manifest file that every file has a unique nonce. It will provide an error message when a collision occurred during construction and pick another random nonce. At orders of magnitude higher than 2^64, one might have delays in picking a nonce. If you are looking at creating a manifest with greater than 2^128 files, the creation program will fail (good luck finishing in your lifetime anyway). When checking the manifest, it checks for duplicated nonces. This makes it very hard to guess the private key from a large manifest. If across all of your manifests you had a line that matched the name, date of last changed, length, nonce which was signed with the same private key, one could substitute one of these lines for the other allowing an attacker to change a file to the one captured in the other manifest. The odds of this are 1/ 2^384 (so low to be impractical with a lifetime of human computing power).<br>

Don't know limits of hashing:<br>
When working on a live linux system /proc/kcore can be very large (e.g. 128TB). Need to see if it can hash a file that big!<br>

Magic string:<br>
Do not include this string as the only string in your header. It will cause the check programs to stop early:<br>
`87e00106e0c012cd1c0216292d070989125c3f215b73429fa8a3f247b8520f3110e53db9d4e139328ba8f00321117fbda14bb317ee498909a393fafce4bd631e7966f4be302d1818b12bf22e32c38fc4cc594c310c2de480df29b2ca3a4b2c470eb0610e309740ef831f18969c9fc97f7d7dfc8d98110b5f8064393605b1e20110dc90bd9d20e87a32e5fbd611bf071bf61d8fb1a1c0352ff82974b989ea91e9
303eb1e75831a7bd4f3aebce5857bfcb7cf917b948caea4ea7e8530938818449cc8856c039599e757b437ab94f2818c8a91cf669abe6abbb629ed651301f4a86ea218d128451dabc5b06ccdd38e8a729c00458e7c9b777a33db51d2f61047444`<br>



<h1>Possible Roadmap <br></h1>
Right now there is only one signing algorithm that is in use. Thinking of adding a post quantum crypto algorithm option.<br>
