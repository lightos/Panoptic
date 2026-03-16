# Panoptic demo recording
# Run: vhs demo.tape

Output demo.gif
Set FontSize 16
Set Width 1200
Set Height 800
Set Theme "Molokai"
Set TypingSpeed 40ms
Set Padding 20

Hide
Type "cd /home/manchine/dev/Panoptic"
Enter
Sleep 1s
Show
Type "python3 -m panoptic --url 'http://localhost:8080/classic.php?file=test.txt' --prefix '../../../' --auto"
Enter
Sleep 13s
