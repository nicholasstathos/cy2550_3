## Puzzle 1

**Final plaintext:** I got a jar of dirt

### Operations

1. **Vigenère cipher w the  key "dirt"**
   The repeating 4-character pattern in the ciphertext lined up with a 4-letter key, and the hint gave it away as "dirt." Decoding with that key was the first step.

2. **QWERTY substitution**
   This maps the keyboard layout back onto the regular alphabet, so Q becomes A, W becomes B, E becomes C, and so on. Upper and lowercase both had to be substituted, since every fourth character was lowercase.

3. **Base64**
   The trailing equals sign is Base64 padding, so the next step was decoding from Base64.

4. **Binary**
   That gave a string of 8-bit binary groups separated by spaces. Converting each group to its ASCII character produced the final message.

## Puzzle 2

**Final plaintext:** NOT ALL TREASURES SILVER AND GOLD MATE

### Operations in order

1. **Substitution**
   The linked key maps digits to letters so I swapped them all like this C=0, Y=1, B=2, E=3, R=4, I=5, S=6, F=7, U=8, N=9. Spaces stayed as they were.

2. **Columnar transposition, 5 columns**
   The 5 wide box hint pointed to a 5-column grid. I filled the text into the columns top to bottom and read it back out row by row. Again spaces stayed

3. **Multi-tap phone keypad**
   After the transposition I had groups of repeated digits which are letters typed on an old phone keypad. 6 is M, 555 is L, and 4 is G. A 0 is a space.

4. **Atbash**
   Flipping the alphabet a to z to decode. 
