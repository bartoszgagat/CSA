# Program will execute (cisco) commands on (cisco) devices
# first concept John Kull
# author Bartosz Gagat
#
#  
# import modules needed and set up ssh connection parameters
import paramiko
import datetime
import PySimpleGUI as sg
#import configparser
import webbrowser
import os
import sys
from socket import gethostbyname,gaierror
from cryptography.fernet import Fernet

# define variables
user1 = []
password1=[]
secret1 = []
ML1=[]
iplist= [""]
cmd_list =[""]
User_name=[""]
port = 22
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
time_now  = datetime.datetime.now().strftime('%m_%d_%Y_%H_%M_%S')

#Main ssh function 
#Below function will connect to all ips from iplist1 with username1 and password1, and execute commands from comand_list1
#Due restriction in ssh.connect only one command is allowed per session - loop in loop is used

def write_key():
    """
    If key file not exists generates a key and save it into a file into "config" directory
    """
    if not os.path.isfile(os.path.abspath(os.getcwd())+"\\config\\""key.key"):
        key = Fernet.generate_key()
        with open(os.path.abspath(os.getcwd())+"\\config\\""key.key", "wb") as key_file:
            key_file.write(key)
        

def load_key():
    """
    Loads the key from the "config" directory named `key.key`
    """
    return open(os.path.abspath(os.getcwd())+"\\config\\""key.key", "rb").read()

def encrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it encrypts the file and write it
    """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
        # encrypt data
        encrypted_data = f.encrypt(file_data)
        # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def decrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it decrypts the file and write it
    """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)





def bg_connect(iplist1,username1,password1,cmd_list1):
    """
    Loop in loop for create ssh connection and execute  commands on devices 
    """
    for ip in range (len(iplist1)):
        try:
            time_now  = datetime.datetime.now().strftime('%m_%d_%Y_%H_%M_%S')
            for command in range (len(cmd_list1)):
                
                
                ssh.connect(hostname=iplist1[ip], username=username1, password=password1, port=port, banner_timeout=200)
                stdin, stdout, stderr = ssh.exec_command(cmd_list1[command])
                
                if not os.path.isdir('output') :
                    os.makedirs('output')
                outfile = open(outfilepath + '\\output\\' + iplist1[ip] + "_" + time_now + ".txt", "a")
                window['-ML3-'].print('Working on  ',iplist1[ip])
                outfile.write('############################Output from SSH_SCA (Author: Bartosz Gagat)   ' + cmd_list1[command] + '#################################\n')
                
                for line in iter(lambda: stdout.readline(2048), ""):
                    outfile.write(line)
                    
                outfile.write('\n##############################################################################################\n')
                    
                ssh.close()
                outfile.close()
            if os.path.exists(outfilepath + '\\output\\' + iplist1[ip] + "_" + time_now + ".txt") :
                window['-ML3-'].print('Job done!\n File created: ',outfilepath + '\\output\\' + iplist1[ip] + "_" + time_now + ".txt", 'created')
        except paramiko.AuthenticationException:
            window['-ML3-'].print("Authentication failed, please verify your credentials",background_color='red')
        except paramiko.SSHException as sshException:
            window['-ML3-'].print("Unable to establish SSH connection: %s" , sshException,background_color='red')
        except paramiko.BadHostKeyException as badHostKeyException:
            window['-ML3-'].print("Unable to verify server's host key: %s" , badHostKeyException,background_color='red')
        except gaierror:
            window['-ML3-'].print("Getaddrinfo failed (no route to target host?)" , background_color='red')
        
        except:
            
            window['-ML3-'].print('General error : guru meditation   ',iplist1[ip], cmd_list1[command],background_color='red')
            

def bg_save(iplist1,username1,password1,cmd_list1):
    """
    Save list of machines, list of commands, secrets, encrypt secrets
    """
    if not os.path.isdir('config') :
        os.makedirs('config')
    outfile = open(outfilepath + '\\config\\' "ip_list.txt", "w")
    for ip in range (len(iplist1)):
        
        outfile.write(iplist1[ip]+"\n")
    window['-ML3-'].print('List of machines saved in ', outfilepath,'\\config\\' "ip_list.txt")
    outfile.close()

    outfile = open(outfilepath + '\\config\\' "cmd_list.txt", "w")
    for command in range (len(cmd_list1)):
        outfile.write(cmd_list1[command]+"\n")
    window['-ML3-'].print('List of commands saved in ', outfilepath,'\\config\\' "cmd_list.txt")
    outfile.close()

    outfile = open(outfilepath + '\\config\\' "sec_list.txt", "w")
    outfile.write(username1+"\n")
    outfile.write(password1+"\n")
    outfile.close()
    
    window['-ML3-'].print('List of secrets saved in ', outfilepath,'\\config\\' "sec_list.txt")
    # uncomment this if it's the first time you run the code, to generate the key
    write_key()
    # load the key
    key = load_key()
    # file name
    outfile = (outfilepath+'\\config\\'+"sec_list.txt")
    # encrypt it
    encrypt(outfile, key)
    


            







def bg_button_execute():
    """
    Takes data from windows, call bg_connect
    """
    iplist= [""]
    cmd_list =[""]
    #Send Multiline -ML1- to list iplist
    
    iplist.append(values["-ML1-"])
    #print (iplist)
    list_of_ips=iplist[1].splitlines()   #Create new list with separate strings
    #print (values ["-USER-"])

    cmd_list.append(values["-ML2-"])
    list_of_commands=cmd_list[1].splitlines()
    #print ('lista komend',list_of_commands,values["-ML2-"])

    bg_connect(list_of_ips,values["-USER-"],values["-PW-"],list_of_commands)



#Gui begining

def bg_button_save():
    """
    Read from windows, format variables, call save function
    """
    try:
        iplist.append(values["-ML1-"])
        list_of_ips=iplist[1].splitlines()
        cmd_list.append(values["-ML2-"])
        list_of_commands=cmd_list[1].splitlines()
        bg_save(list_of_ips,values["-USER-"],values["-PW-"],list_of_commands)
    except:    
        window['-ML3-'].print('File save error',background_color='red')
 




def bg_button_load():
    """
    Read files, send values to windows
    """
    window['-ML1-'].update('')
    try:
        with open(outfilepath + '\\config\\' "ip_list.txt") as f:
            for line in f:
                window['-ML1-'].print(line.strip())
        f.close()

        window['-ML2-'].update('')
        with open(outfilepath + '\\config\\' "cmd_list.txt") as f:
            for line in f:
                window['-ML2-'].print(line.strip())
        f.close()


        key = load_key()
        outfile = (outfilepath+'\\config\\'+"sec_list.txt")
        decrypt(outfile,key)
        with open(outfile) as f:
            calosc=f.readlines()
            window['-USER-'].update(value=calosc[0].strip())
            window['-PW-'].update(value=calosc[1].strip())
        encrypt(outfile,key)
        f.close()
        window['-ML3-'].print('Data loaded from ', outfilepath+'\\config\\')
    except:    
        window['-ML3-'].print('File load error',background_color='red')
    

#Main part of exe


outfilepath = os.getcwd() 
sg.set_options(element_padding=(0, 0))      

# ------ Menu Definition ------ #      
menu_def = [['File', ['Load', 'Save', 'Exit'  ]],      
            ['Help', ['About...', 'How to contact author','How to contact technical helpdesk'], ]]   

layout = [       
        [sg.Menu(menu_def, )],      
        [sg.Text('List of machines',size=(24,1)),sg.Text('List of commands',size=(24,1)),sg.Text('Output',size=(48,1)),sg.Push()],
        [sg.Multiline(size=(25,10), key='-ML1-'), (sg.Multiline(size=(25,10), key='-ML2-')),(sg.Multiline(size=(58,10),key='-ML3-'))],
        [sg.Text('Username:',size=(10,1)),sg.Input(size=(43),key='-USER-')],
        [sg.Text('Password:',size=(10,1)),sg.Input(size=(43),password_char='*', key='-PW-')],
        [sg.Button('Execute', button_color = ('black on red'), bind_return_key=True)] 
           ]

window = sg.Window('Ssh SHOW Command Automatizer - BETA ver-', layout)

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Exit':
        break
    if event == 'Execute':
        bg_button_execute()
    if event =='Save':
        bg_button_save()
        #sg.popup('Save is not working in aplha version')
    if event =='Load':
        bg_button_load()
        

    if event == 'About...':      
            sg.popup('SSH show command automatizer', 'Version 1.1 -BETA-', 'Author: Bartosz Gagat', 'Author is learnig python ', 'License: Freeware')
    if event == 'How to contact author':         
            webbrowser.open('www.linkedin.com/in/bartoszgagat//', new=0)
    if event == 'How to contact technical helpdesk':
            webbrowser.open('https://www.youtube.com/watch?v=4V2C0X4qqLY', new=0)
window.close()



