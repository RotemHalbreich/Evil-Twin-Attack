![evil-twin](https://user-images.githubusercontent.com/66558110/168109529-d1afbe18-5563-4a45-954e-9c43d06e2723.jpg)
# 👼 *Evil Twin Attack* 😈
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
## :pencil: *Project's Authors:*
 *Eyal Levi   -  GitHub: https://github.com/LeviEyal* | *Rotem Halbreich  -  GitHub: https://github.com/RotemHalbreich* | *Moshe Crespin  -  GitHub: https://github.com/mosheCrespin*
------------------------------------------------------|------------------------------------------------------|------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------------------

## ❗ *About The Project:*
### *In this project we've created a program in Python which attacks a user over the internet in order to steal his login information. We've also created a defense program for protecting the user from such an attack.*


## :bar_chart: *Project's Diagram:*
![EvilTwin](https://user-images.githubusercontent.com/66558110/168108301-7f8a238e-a617-48b8-9b9e-166647628f34.png)


## :white_check_mark: *Initialize The Project:*
### *What are the Hardware requirements?*
* *A Laptop with Linux OS*
* *Network Interface Controller (NIC) - Tenda in our case.*

*Clone the project using the Command Line by typing the command:*
`git clone https://github.com/LeviEyal/EvilTwin.git`
* *Run* `sudo install python3` *in the Command Line to download Python.*
* *Run* `sudo sh Requierments.sh` *in the Command Line to download all the requirements.*
* *Run* `sudo python3 access_point.py` *in the Command Line to execute the program.*

## ⚔️ *__ATTACK:__*
* *Step 1: Choose an interface (NIC) for monitoring, and put it in 'Monitor Mode'.*
* *Step 2: Choosing the Access Point (Wifi) we wish to attack.*
* *Step 3: Checking whether the chosen AP has a client connected to it. -> [Pick a Client (MAC)]*
* *Step 4: Running the Deauthentication Attack script (Sends packets non-stop).*
* *Step 5: Puts the interface back in 'Managed Mode'.*

## 🛡️ *__DEFENSE:__*  
* *Step 1:  Choosing an interface to put in 'Monitor Mode'.*
* *Part 2: Defense against Deauthentication Attack.*
* *Step 3: Sniffing the packets and checking for Deauthentication Attack.*
* *Step 4: Puts the interface back in 'Managed Mode'.*

--------------------------------------------------------------------------------------------------------------------------------------------------------------------

# :octocat: *Enjoy, and please share!* :smile:
