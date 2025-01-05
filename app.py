from flask import Flask, render_template, jsonify
import ntag424_programmer as ntag
import subprocess
import os

app = Flask(__name__)

reader_connected = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_reader_state')
def check_reader_state():
    global reader_connected
    return jsonify({
        'reader_connected': reader_connected
    })

@app.route('/connect_reader')
def connect_reader():
    global reader_connected
    try:
        status = ntag.ReaderOpen()
        if status == 0:
            reader_connected = True
            return jsonify({
                'status': 'success', 
                'message': 'Reader connected successfully',
                'reader_connected': True
            })
        else:
             return jsonify({
                'status': 'error', 
                'message': f'Failed to connect: {ntag.UFRStatus2String(status)}',
                'reader_connected': False
            })
    except Exception as e:
        return jsonify({
            'status': 'error', 
            'message': str(e),
            'reader_connected': False
        })

@app.route('/disconnect_reader')
def disconnect_reader():
    try:
        ntag.ReaderClose()
        reader_connected = False
        return jsonify({
            'status': 'success', 
            'message': 'Reader disconnected successfully',
            'reader_connected': False
        })
    except Exception as e:
        return jsonify({
            'status': 'error', 
            'message': str(e),
            'reader_connected': True
        })

@app.route('/program_tag')
def program_tag():
    global reader_connected
    if not reader_connected:
        return jsonify({
            'status': 'error',
            'message': 'Reader not connected'
        })
    
    try:

        velcro_boot_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'velcro_boot')
        
        # Execute make command in the velcro_boot directory
        process = subprocess.Popen(['make'], cwd=velcro_boot_path)
        process.wait()  # Wait for the make command to complete

        if process.returncode != 0:
            return jsonify({
                'status': 'error',
                'message': 'Make command failed'
            })

        # Execute make upload_assets command
        process = subprocess.Popen(['make', 'upload_assets'], cwd=velcro_boot_path)
        process.wait()  # Wait for the upload_assets command to complete

        if process.returncode != 0:
            return jsonify({
                'status': 'error',
                'message': 'Make upload_assets command failed'
            })

        
        # Get card UID
        uid = (ntag.c_ubyte * 11)()
        sak = ntag.c_ubyte()
        uid_size = ntag.c_ubyte()
        card_uid_str = str()

        status = ntag.GetCardIdEx(sak, uid, uid_size)
        if status != 0:
            return jsonify({
                'status': 'error',
                'message': 'Failed to retrieve card UID'
            })

        card_uid_str = ntag.uid_to_string(uid, uid_size)

        # Read canister ID from json file
        canister_ids_path = os.path.join(velcro_boot_path, '.dfx', 'local', 'canister_ids.json')
        try:
            with open(canister_ids_path, 'r') as f:
                import json
                canister_data = json.load(f)
                canister_id = canister_data['velcro_boot']['local']
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Failed to read canister ID: {str(e)}'
            })


         
        # Form SDM NDEF Payload with the dynamic canister ID
        uri = f"http://{canister_id}.localhost:4943/"
        
        # Form SDM NDEF Payload
        # uri = "http://be2us-64aaa-aaaaa-qaabq-cai.localhost:4943/"

        formed_result = ntag.form_sdm_ndef_payload(uri)
        sdm_payload = formed_result["sdm_payload"]
        
        # Add additional parameters
        extended_payload_result = ntag.add_additional_ndef_payload_parameter(sdm_payload, "", "")
        extended_payload = extended_payload_result["extended_payload"]
        extended_payload_length = extended_payload_result["extended_payload_length"]

        # Write SDM payload12345678
        file_no = ntag.c_ubyte(2)
        key_no = ntag.c_ubyte(0)
        communication_mode = ntag.c_ubyte(0)
        status = ntag.nt4h_set_global_parameters(file_no, key_no, communication_mode)

        default_aes_key = (ntag.c_ubyte * 16)()
        ntag.memset(default_aes_key, 0, ntag.ctypes.sizeof(default_aes_key))
        write_data_buffer = (ntag.c_ubyte * len(extended_payload))(*extended_payload)
        write_len = ntag.c_uint16(extended_payload_length)
        bytes_written = ntag.c_uint16()
        auth_mode = ntag.c_ubyte(ntag.T4T_AUTHENTICATION["T4T_PK_PWD_AUTH"])
        
        status = ntag.LinearWrite_PK(write_data_buffer, 0, write_len, bytes_written, auth_mode, default_aes_key)
        if status != 0:
            return jsonify({
                'status': 'error',
                'message': f'Failed to write NDEF message: {ntag.UFRStatus2String(status)}'
            })

        # Change SDM settings
        status = ntag.nt4h_tt_change_sdm_file_settings_pk(
            default_aes_key,
            file_no,
            key_no,
            ntag.c_ubyte(3),  # communication_mode
            ntag.c_ubyte(0),  # new_communication_mode
            ntag.c_ubyte(0x0E),  # read_key_no
            ntag.c_ubyte(0),  # write_key_no
            ntag.c_ubyte(0),  # read_write_key_no
            ntag.c_ubyte(0),  # change_key_no
            ntag.c_ubyte(1),  # uid_enable
            ntag.c_ubyte(1),  # read_ctr_enable
            ntag.c_ubyte(0),  # read_ctr_limit_enable
            ntag.c_ubyte(0),  # enc_file_data_enable
            ntag.c_ubyte(0x0E),  # meta_data_key_no
            ntag.c_ubyte(0),  # file_data_read_key_no
            ntag.c_ubyte(0),  # read_ctr_key_no
            formed_result["uid_offset"],
            formed_result["read_ctr_offset"],
            ntag.c_uint(0),  # picc_data_offset
            ntag.c_uint(formed_result["mac_offset"]),
            ntag.c_uint(0),  # enc_offset
            ntag.c_uint(0),  # enc_length
            formed_result["mac_offset"],
            ntag.c_uint(0),  # read_ctr_limit
            ntag.c_ubyte(0),  # tt_status_enable
            ntag.c_uint(0)  # tt_status_offset
        )

        if status != 0:
            return jsonify({
                'status': 'error',
                'message': f'Failed to set SDM settings: {ntag.UFRStatus2String(status)}'
            })

        return jsonify({
            'status': 'success',
            'message': f'Tag programmed successfully. UID: {card_uid_str}',
            'uid': card_uid_str
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error during programming: {str(e)}'
        })


@app.route('/get_principal')
def get_principal():
    try:
        # Run dfx identity get-principal command
        result = subprocess.run(['dfx', 'identity', 'get-principal'], 
                              capture_output=True, 
                              text=True)
        
        if result.returncode == 0:
            # Command succeeded
            return jsonify({
                'status': 'success',
                'message': 'Principal ID retrieved successfully',
                'principal': result.stdout.strip()
            })
        else:
            # Command failed
            return jsonify({
                'status': 'error',
                'message': f'Failed to get principal: {result.stderr}'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error executing dfx command: {str(e)}'
        })

if __name__ == '__main__':
    app.run(debug=True, port=5000)