#from turtle import delay
import time
import proto_ecdh
import binascii
import os
import shutil

path_pk = 'local\listed_key.txt'
def verif_pub_key():
    lpk_res:bytes    
    if not os.path.exists(path_pk):                    
        key_doc = open(path_pk,'x')
        key_doc.close()
        status = False
        lpk_res = ''
    else:
        key_doc = open(path_pk,'r')
        cer_path = key_doc.read()
        key_doc.close()
        if not os.path.exists(cer_path):
            status = False
            lpk_res = ''
        else:
            key_doc = open(cer_path, 'rb')
            lpk_res = key_doc.read()
            key_doc.close()
            status = True
    return (lpk_res, status)

path_ok = 'local\map_signk.txt'
def verif_other_signk():
    if not os.path.exists(path_ok):
        key_doc = open(path_ok,'x')
        key_doc.close()
        status = False
        lpk_res = ''
    else:
        key_doc = open(path_ok,'r')
        cer_path = key_doc.read()
        key_doc.close()
        if not os.path.exists(cer_path):
            status = False
            lpk_res = ''
        else:
            key_doc = open(cer_path, 'rb')
            lpk_res = key_doc.read()
            key_doc.close()
            status = True
    return (lpk_res, status)

def start_menu():
    # Menu inicial
    print('#--------Sign Key for other users---------#')
    pb_lst, status = verif_other_signk()
    if not status: 
        print('No other keys')
    else:
        print(pb_lst.decode())
    print('#-----------Public Session Key------------#')
    pb_lst, status = verif_pub_key()
    if not status:
        print('No public key')
    else:
        print(pb_lst.decode())
    print('#-----------Modulo sec_app menu-----------#')
    print('1 - Begin session')
    print('2 - Encrypt a msg (AES - GCM)')
    print('3 - Encrypt a file (AES - GCM)')
    print('4 - Dencrypt a msg (AES - GCM)')
    print('5 - Dencrypt a file (AES - GCM)')
    print('6 - Exit')
    print('#-----------------------------------------#')
    while True:
        menu_interac = input('Choose an option> ')
        if menu_interac.isnumeric():
            menu_interac = int(menu_interac)
            if menu_interac >= 1 and menu_interac <= 6:
                break
        print('Bad option')
    return menu_interac


local_k = ['local\lcl_prv.cer','local\lcl_prv.cer']
def ini_ver ():
    print('Inicialzing..')
    if os.path.exists('serv_sec.cer'):
        os.remove('serv_sec.cer')
    if os.path.exists('priv_key_sec.cer'):
        os.remove('priv_key_sec.cer')
    if os.path.exists('pub_key_sec.cer'):
        os.remove('pub_key_sec.cer')
    if os.path.exists('temp'):
        shutil.rmtree('temp')
    os.mkdir('temp')

    if not os.path.exists('local'):
        os.mkdir('local')        
    if not os.path.exists('output'):
        os.mkdir('output')
    if not os.path.exists('input'):
        os.mkdir('input')
    
    if (not os.path.exists(local_k[0])) or (not os.path.exists(local_k[1])):
        print('Local keys not found. Generating new local keys..')
        pss_lcl = input('Insert key password>')
        if len(pss_lcl) == 0:
            ed_pr_k, ed_pb_k = proto_ecdh.ed_key()
        else:
            ed_pr_k, ed_pb_k = proto_ecdh.ed_key(pss_lcl)        
        key_doc = open('local\lcl_prv.cer','wb')
        key_doc.write(ed_pr_k)
        key_doc.close()
        key_doc = open('local\lcl_pub.cer','wb')
        key_doc.write(ed_pb_k)
        key_doc.close()
        key_doc = open('output\other_key.cer','wb')
        key_doc.write(ed_pb_k)
        key_doc.close()
        print('Local keys generated!')
    else:
        print('Local keys ok.')

# Init
pub_key_work:any
os.system('cls' if os.name == 'nt' else 'clear')
ini_ver()
menu_interac = start_menu()
while True:
    match menu_interac:
        case 1:
            print('Starting the session..')
            # key_pss = input('Insert key password>')
            # if len(key_pss) == 0:
            #     key_ring = proto_ecdh.key_gen()
            # else:
            #     key_ring = proto_ecdh.key_gen(key_pss)
            key_ring = proto_ecdh.key_gen()
            key_doc = open('temp\priv_key_sec.cer','wb')
            key_doc.write(key_ring[0])
            key_doc.close()
            key_doc = open('temp\pub_key_sec.cer','wb')
            key_doc.write(key_ring[1])
            key_doc.close()
            key_doc = open('output\serv_sec.cer','wb')
            key_doc.write(key_ring[1])
            key_doc.close()
            print('Waiting for server response..', end=' ')
            while True:
                if not os.path.exists('temp\serv_sec.cer'):                    
                    print('.', end='', flush=True)
                    time.sleep(0.950)
                    continue
                else:
                    key_doc = open('temp\serv_sec.cer','rb')
                    key_bytes = key_doc.read()
                    key_doc.close()
                    reg = open(path_pk, 'w')
                    reg.write('temp\serv_sec.cer')
                    reg.close()                
                    break
            if not os.path.exists('local\other_key.cer') or not os.path.exists(f'{path_ok}'):
                print('Sharing sign key..', end=' ')
                while True:
                    if not os.path.exists('local\other_key.cer'):
                        print('.', end='', flush=True)
                        time.sleep(0.950)
                        continue
                    else:
                        key_doc = open('local\other_key.cer','rb')
                        other_key = key_doc.read()
                        key_doc.close()
                        reg = open(path_ok, 'w')
                        reg.write(f'local\other_key.cer')
                        reg.close() 
                        break      
        case 2:
            print('Encrypting a msg..')
            pb_lst, status = verif_pub_key()
            if not status:
                print('No session key!')
                time.sleep(0.750)
            else:
                if not os.path.exists('temp\priv_key_sec.cer'):
                    print('No Private key!')
                else:
                    dat_msg = input('Type your menssage> ')
                    priv_pass = input('Type your password>')
                    key_doc = open('temp\priv_key_sec.cer','rb')
                    key_priv_bytes = key_doc.read()
                    key_doc.close()
                    priv_loaded_key = proto_ecdh.import_priv_key(key_priv_bytes)
                    if priv_loaded_key is None:
                        print('Fail Encrypt')
                    else:
                        derived_key = proto_ecdh.cryp_key(priv_loaded_key,pb_lst)
                        iv, data_sec, tag = proto_ecdh.in_cryp(dat_msg.encode(),derived_key)
                        key_doc = open('local\lcl_prv.cer','rb')
                        ed_prv_bytes = key_doc.read()
                        key_doc.close()
                        res_sign, pss_ok = proto_ecdh.make_sign(ed_prv_bytes, priv_pass, tag)
                        if not pss_ok:
                            print('Fail Encrypt, wrong pass')
                        else:
                            print('IV from msg pgp> ',binascii.b2a_hex(iv))
                            print('Tag from msg pgp> ', binascii.b2a_hex(tag))
                            print('Sign from msg> ',binascii.b2a_hex(res_sign))  
                            print('Msg crypted', binascii.b2a_hex(data_sec))
                            while True:
                                op = ['y', 'n']
                                resp = input('Save in file?[y/n]>')
                                if resp.lower() not in  op or resp.lower() not in op:
                                    print('Invalid answer')
                                    continue
                                elif resp.lower() == 'y':
                                    out_files = open('output\iv.cer', 'wb')
                                    out_files.write(iv)
                                    out_files.close()
                                    out_files = open("output\\tag.cer", 'wb')
                                    out_files.write(tag)
                                    out_files.close()
                                    out_files = open('output\sign.cer', 'wb')
                                    out_files.write(res_sign)
                                    out_files.close()
                                    out_files = open('output\msg.txt.pgp', 'wb')
                                    out_files.write(data_sec)
                                    out_files.close()
                                    break
                                else:
                                    print('No save')
                                    break
            time.sleep(0.750)
        case 3:
            print('Encrypting a file..')
            # Verificar chave de sessão
            pb_lst, status = verif_pub_key()
            if not status:
                print('No session key!')
                #time.sleep(0.750)
            else:
                if not os.path.exists('temp\priv_key_sec.cer'):
                    print('No Private key!')
                else:
                    # Localizar arquivo a ser criptografado
                    file_name = input('Type the file name with extension> ')
                    if not os.path.exists(f'{file_name}'):
                        print('File not fould')
                    else:
                        # Manipular bits desse documento
                        doc_read = open(f'{file_name}', 'rb')
                        doc_bytes = doc_read.read()
                        doc_read.close()
                        # Inserindo password da chave privada para assinatura
                        priv_pass = input('Type your private key password>')
                        key_doc = open('temp\priv_key_sec.cer','rb')
                        key_priv_bytes = key_doc.read()
                        key_doc.close()
                        priv_loaded_key = proto_ecdh.import_priv_key(key_priv_bytes)
                        if priv_loaded_key is None:
                            print('Fail Encrypt')
                        else:
                            # Gerando chave secreta de criptografia da sessão por DH.
                            derived_key = proto_ecdh.cryp_key(priv_loaded_key,pb_lst)
                            # Criptografando os dados do documento
                            iv, data_sec, tag = proto_ecdh.in_cryp(doc_bytes,derived_key)
                            # Carregando chave privada de assinatura e gerando a assinatura.
                            key_doc = open('local\lcl_prv.cer','rb')
                            ed_prv_bytes = key_doc.read()
                            key_doc.close()
                            res_sign, pss_ok = proto_ecdh.make_sign(ed_prv_bytes, priv_pass, tag)
                            if not pss_ok:
                                print('Fail Encrypt, wrong pass')
                            else:
                                # Salvando resultados da criptografia..
                                out_res = open (f'{file_name}.pgp', 'wb')
                                out_res.write(data_sec)
                                out_res.close()
                                print(f'{file_name}.pgp created!')
                                print('IV from file pgp> ',binascii.b2a_hex(iv))
                                print('Tag from file pgp> ', binascii.b2a_hex(tag))
                                print('Sign from msg> ',binascii.b2a_hex(res_sign))                         
                                while True:
                                    op = ['y', 'n']
                                    resp = input('Save in file?[y/n]>')
                                    if resp.lower() not in  op or resp.lower() not in op:
                                        print('Invalid answer')
                                        continue
                                    elif resp.lower() == 'y':
                                        out_files = open('output\iv.cer', 'wb')
                                        out_files.write(iv)
                                        out_files.close()
                                        out_files = open('output\\tag.cer', 'wb')
                                        out_files.write(tag)
                                        out_files.close()
                                        out_files = open('output\sign.cer', 'wb')
                                        out_files.write(res_sign)
                                        out_files.close()
                                        break
                                    else:
                                        print('No save')
                                        break
            time.sleep(0.750)
        case 4:
            print('Not yet.')
        case 5:
            print('Decrypting a file..')
            # Carregando chave de sessão e a chave publica da assinatura.
            pb_lst, status = verif_pub_key()
            other_pbk, status = verif_other_signk()
            if not status:
                print('No pub or session key!')
                #time.sleep(0.750)
            else:
                if not os.path.exists('temp\priv_key_sec.cer'):
                    print('No Private key!')
                else:
                    dec_iv:bytes
                    dec_tag:bytes
                    # Buscando pelos arquivos base para decriptar os dados.
                    while True:
                        op = ['y', 'n']
                        resp = input('Search for IV, tag and sign file?[y/n]>')
                        if resp.lower() not in  op or resp.lower() not in op:
                            print('Invalid answer')
                            continue
                        elif resp.lower() == 'y':
                            if not os.path.exists('input\iv.cer') or not os.path.exists('input\\tag.cer') or not os.path.exists('input\sign.cer'):
                                print('Cant found iv.cer, tag.cer or sign.cer.')
                            else:
                                out_file = open('input\iv.cer','rb')
                                dec_iv = out_file.read()
                                out_file.close()
                                out_file = open('input\\tag.cer','rb')
                                dec_tag = out_file.read()
                                out_file.close()
                                out_file = open('input\sign.cer','rb')
                                dec_sign = out_file.read()
                                out_file.close()
                            break
                        else:
                            print('Manual input values..')
                            input_iv = input('Insert IV value (Hexa representation in ascii)> ')
                            dec_iv = binascii.a2b_hex(input_iv.encode())
                            input_tag = input('Insert Tag value (Hexa representation in ascii)> ')
                            dec_tag = binascii.a2b_hex(input_tag.encode())
                            input_sign = input('Insert Sign value (Hexa representation in ascii)> ')
                            dec_sign = binascii.a2b_hex(input_tag.encode())
                            break
                    # Carregando o arquivo criptografado
                    file_name = input('Type the file name with extension> ')
                    if not os.path.exists(f'{file_name}'):
                        print('File not fould')
                    else:
                        doc_read = open(f'{file_name}', 'rb')
                        doc_enc_bytes = doc_read.read()
                        doc_read.close()
                        # Coletando a senha
                        #priv_pass = input('Type your private key password>')
                        # Carregando a chave de sessão
                        key_doc = open('temp\priv_key_sec.cer','rb')
                        key_priv_bytes = key_doc.read()
                        key_doc.close()
                        priv_loaded_key = proto_ecdh.import_priv_key(key_priv_bytes)
                        if priv_loaded_key is None:
                            print('Fail Decrypt')
                        else:
                            # Verificando a assinatura do documento
                            tag_ver = dec_tag
                            sign_status = proto_ecdh.sign_ver(other_pbk, dec_sign, tag_ver)
                            if sign_status:                                
                                derived_key = proto_ecdh.cryp_key(priv_loaded_key,pb_lst)
                                data_free = proto_ecdh.de_cryp(doc_enc_bytes,derived_key,dec_iv,dec_tag)
                                if '.pgp' in file_name:
                                    n_file_name = file_name.removesuffix('.pgp')
                                else:
                                    n_file_name = file_name
                                out_res = open (f'{n_file_name}', 'wb')
                                out_res.write(data_free)
                                out_res.close()
                                print(f'{n_file_name} has been rescued!')
                            else:
                                print('Invalid Signature!') 
            time.sleep(0.750)
        case 6:
            print('Exiting..')
            if os.path.exists('temp\serv_sec.cer'):
                os.remove('temp\serv_sec.cer')
            if os.path.exists('temp\priv_key_sec.cer'):
                os.remove('temp\priv_key_sec.cer')
            if os.path.exists('temp\pub_key_sec.cer'):
                os.remove('temp\pub_key_sec.cer')
            break
        case _:
            print('Menu fail!')
            break
    os.system('cls' if os.name == 'nt' else 'clear')
    #print(len(pub_key_work))
    menu_interac = start_menu()
