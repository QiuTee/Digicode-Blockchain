from rest_framework.decorators import APIView , action
from rest_framework import status, viewsets
from rest_framework.response import Response 
from rest_framework.generics import GenericAPIView
from backend_app.serializer import *
from .pin import create_pin 
from .emails import send_otp_via_email , send_otp_via_email_for_reset , sending_email , generate_OTP
from rest_framework_simplejwt.tokens import RefreshToken
from email import *
from django.core.exceptions import ObjectDoesNotExist
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import authenticate , login
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.hashers import check_password
import bcrypt
from .functions import *
from .connect_w3 import connect_to_w3
from decimal import Decimal
from decouple import config
from .pending import get_pending_transactions
from .process import process_transaction
from django.http import HttpResponse
from decimal import Decimal
from rest_framework.parsers import JSONParser
from django.conf import settings

class LoginAPI(GenericAPIView):
    def post(self, request):
        w3 = connect_to_w3()
        serializer = LoginSerializer(data=request.data)
        try :
            # Check the validity of input data from the serializer
            if serializer.is_valid(raise_exception=True) :
                # lấy dữ liệu đã được xác thực từ serializer
                username = serializer.validated_data['username']
                password = serializer.validated_data['password']
                # Get user information from login name
                user = User.objects.get(username=username)
                if user.is_verified : 
                # Check the password is correct
                    if check_password(password, user.password):
                        user_profile = UserProfile.objects.get(user_id = user.id)
                        refresh = RefreshToken.for_user(user)
                        refresh['username'] = user.username
                        wallet = w3.to_checksum_address(user.user_address)
                        # Get the account balance from the user's wallet
                        balance = w3.from_wei(w3.eth.get_balance(wallet), "ether")
                        amount = Decimal(balance)
                        amount_decimal = "{:.50f}".format(amount).rstrip('0')
                        return Response({
                            'status': '200 OK',
                            'data': {
                                'id': user.id,
                                'username': user.username,
                                'email': user.email,
                                'lastname': user_profile.last_name,
                                'name': user_profile.first_name + " " + user_profile.last_name,
                                'balance': amount_decimal,
                                'address': user.user_address,
                                'refresh': str(refresh),
                                'token': str(refresh.access_token)
                            },
                            'message': 'Login successful'
                        })
                    else :
                        return Response({
                                'message' :'You have enter an invalid username or password',
                                'status' : '401 Unauthorized'
                                })
                else : 
                    return Response ({
                        'message' : 'Invalid username or password', 
                        'status' : '401 Unauthorized'
                    })
            else :
                return Response({ 
                    'message' : 'Username is not valid ' , 
                    'status' : '401 Unauthorized'

                }) 
        except Exception as e :
            return Response({
                            'message' :'You have enter an invalid username or password',
                            'status' : '401 Unauthorized' , 
                            'data' : str(e)
                            })


class RegisterAPI(GenericAPIView):
    def post(self, request) :
        data = JSONParser().parse(request)
        password = data.get('password')
        retypePassword = data.get('retypePassword')

        # check if user exists but not verified
        try: 
            user_exists = User.objects.filter(username = data.get('username')).first()
            if user_exists and not user_exists.is_verified :
                user_exists.delete()
        except Exception as e : 
            return Response ({
                'message' : str(e)
            })

        # Check the match of the password and re-entered password
        if not password == retypePassword :
            return Response({
                'status' : '401 Unauthorized' ,
                'message' : 'Password and retype password is not match'

            })
        serializers = UserInfoSerializer( data = data )
        # print(data)
        try :
            # Check the validity of input data from serializers
            if serializers.is_valid(raise_exception= True) :
                user = serializers.save()
                refresh = RefreshToken.for_user(user)
                send_otp_via_email(serializers.data['email'])
                return Response({
                'status' : '200 OK',
                'data': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email, 
                        'lastname': user.profile.last_name,
                        'name': user.profile.first_name + " " + user.profile.last_name,
                        'phone': user.profile.phoneNumber,
                        'refresh' : str(refresh) , 
                        'token' : str(refresh.access_token) ,
                        'message': 'Please do not skip the last step to verify your account.'
                    }
                })
        except Exception as e:
            return Response(
                {'status' : '401 Unauthorized' ,
                 'error' : 'SignUp Error ',
                 'message' :str(e),
                 'data' : data
                })


        

#verify otp 
class VerifyView(viewsets.ModelViewSet): 
    queryset = User.objects.all() 
    serializers = UserInfoSerializer
    
    @action(detail = False, methods = ['post'])
    def verify_otp(self , request):
        w3 = connect_to_w3()
        code = request.data.get('otp')
        token = request.data.get('token')
        access_token = AccessToken(token)
        token_id = access_token['user_id']
        user = User.objects.get( id = token_id )
        if not user.otp == code : 
            return Response(
                {
                    'status' : '401 Unauthorized' ,
                    'message' : 'OTP is no longer valid ', 
                    'data' : 'otp wrong'
                }
            )
        print(f'Now - {timezone.now()}')
        print(f"Expiration time - {user.expiration_time}")
        if timezone.now() > user.expiration_time : 
            return Response(
                {
                    'status' : '401 Unauthorized ', 
                    'message': 'OTP is no longer valid . Please generate a new otp', 
                    'data' : 'otp wrong'
                }
            )
        
        if not user.is_verified : 
            user.is_verified = True 
            pin = create_pin(user.username)
            # print(pin)
            create_account , address = create_user(w3)
            user.user_address = address
            user.save()
            # Encrypt account information with a PIN and save it to the database
            data = encrypt_private_key(create_account , pin)
            user.data = data
            user.save()
            # Giải mã thông tin tài khoản để kiểm tra tính hợp lệ
            decrypt = decrypt_private_key(w3, user.data, pin)
            return Response(
                {'status': '200 OK', 
                 'message': 'Account verified successfully',
                  'data': f'Please check and remember your pin is being send to your email'               
                }
                )
        return Response({'status': '400', 'message': 'Code is invalid', 'data': 'otp wrong'})
    
    @action(detail=False, methods=['POST'])
    def resend_otp(self, request):
        token = request.data.get('token')
        access_token = AccessToken(token)
        user_id = access_token['user_id']
        user = User.objects.get(id=user_id)

        if user.otp_max_out > timezone.now() and int(user.max_otp_try) == 0:
            return Response({
                'message': 'Max tries reached, try again after 1 hour',
                'status': '400'
            })
        print(user.email)
        new_otp = generate_OTP()
        print(new_otp)
        user.otp = new_otp
        user.expiration_time = timezone.now() + timezone.timedelta(minutes=1)
        max_otp_try = int(user.max_otp_try) - 1
        user.max_otp_try = max_otp_try

        if max_otp_try == 0:
            user.otp_max_out = timezone.now() + timezone.timedelta(hours=1)
        elif max_otp_try == -1:
            user.max_otp_try = settings.MAX_OTP_TRY

        user.save()
        sending_email(new_otp , user.email )
        return Response({
            'message': 'Successfully generate new OTP.',
            'status': '200 OK'
        })


#update profile 
class updateProfile(APIView):
    permissions = [IsAuthenticated]
    
    def put(self, request):
        token = request.data.get('token')
        access_token = AccessToken(token)
        user_id = access_token['user_id']
        user = User.objects.get(id=user_id)
        password = request.data.get('password') 
        confirm_password = request.data.get('confirmPassword')
        print(confirm_password)
        if password == None and confirm_password == None :          
            serializers = UserInfoSerializer(user, data=request.data , partial = True)
            if not serializers.is_valid():
                print(serializers.errors)  # In ra các lỗi để debug
                return Response({
                    'status' : '401 Unauthorized',
                    'message' : 'Update unsuccessful',
                })
            else : 
                serializers.save()
                return Response({ 
                    'status' : '200 OK',
                    'message' : 'Updated profile successfully',
                })
        else : 
            if user.fix_update < timezone.now():
                if password == confirm_password : 
                    serializers = UserInfoSerializer(user, data=request.data , partial = True)
                    if not serializers.is_valid():
                        print(serializers.errors)  # In ra các lỗi để debug
                        return Response({
                            'status' : '401 Unauthorized',
                            'message' : 'Update unsuccessful',
                        })
                    else : 
                        user.fix_update = timezone.now() + datetime.timedelta(days = 30)
                        serializers.save()
                        return Response({ 
                            'status' : '200 OK',
                            'message' : 'Updated profile successfully',
                        })
                else : 
                    return Response({
                        'status' : '401 Unauthorized',
                        'message' : 'Password is not match'
                     })
            else : 
                time_remaining = user.fix_update - timezone.now()
                    # Chuyển đổi thời gian còn lại thành ngày và lấy phần nguyên
                days_remaining = int(time_remaining.total_seconds() // 86400)

                # Lấy phần dư (số giây còn lại sau khi đã trừ đi số ngày)
                remaining_seconds_after_days = time_remaining.total_seconds() % 86400

                # Chuyển đổi phần dư sang phút
                minutes_remaining = int(remaining_seconds_after_days // 60)

                # Thông báo chưa đủ thời gian để cập nhật
                return Response({
                    'status': '401 Unauthorized',
                    'message': f"Please wait {days_remaining} days and {minutes_remaining} minutes before updating."
                })
                        


#forget password 
class ChangePassword(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserInfoSerializer

    @action(detail= False , methods=['POST'])
    def forget_password(self, request) :
        username = request.data.get('username')
        email  = request.data.get('email')
        if not User.objects.filter(username=username , email = email).exists():
            return Response({
                    'status': '401 Unauthorized ',
                    'message': 'User with the given username and email does not exist'
                })
        else:
            if not SaveEmailModel.objects.filter(username= username , email = email ).exists():
                otp_code , expiration_time  = send_otp_via_email_for_reset(email)
                # Add OTP code and expiration time to the request data
                request_data = request.data.copy()
                request_data['code'] = otp_code
                request_data['expiration_time'] = expiration_time
                # Save the email in the email field of the SaveEmailModel table
                serializers = SaveEmailSerializer(data = request_data)
                if serializers.is_valid():
                    serializers.save()
                    # send otp to email 
                    return Response({
                                'status': '200 OK',
                                'message': 'OTP sent successfully'
                            })
            else : 
                user = SaveEmailModel.objects.get(username = username , email = email )
                if ( user.otp_max_try == 0 and user.otp_max_try_time > timezone.now() ) :
                    return Response({ 
                        'status': '401 Unauthorized',
                        'message': 'You have used up all the allowed number of attempts to change your password, please try again after 1 hour.'
                    })
                 
                otp_code , expiration_time  = send_otp_via_email_for_reset(email)
                user.code = otp_code 
                user.expiration_time = expiration_time 
                user.otp_max_try = int(user.otp_max_try) - 1 
                if (user.otp_max_try == 0) : 
                    user.otp_max_try_time = timezone.now() + datetime.timedelta(hours=1)
                elif (user.otp_max_try == -1) : 
                    user.otp_max_try = settings.MAX_OTP_TRY
                user.save()
                return Response({
                    'status': '200 OK',
                    'message': 'OTP sent successfully'
                })
                
        #using reset password in settings
    @action(detail= False , methods=['POST'])
    def reset_password(self , request) :
        first_data = SaveEmailModel.objects.first()
        user = User.objects.get(email=first_data)
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        otp = request.data.get('otp')
        if not first_data.check_run_time() :
            if otp == first_data.code :
                if  confirm_password == password :
                    user.set_password(password)
                    user.save()
                    SaveEmailModel.objects.all().delete()
                    return Response({
                        'status': '200 OK',
                        'message': 'Change password successfully'
                    })
                return Response({
                            'status': '401 Unauthorized ',
                            'message': 'Password not match'
                        })
            return Response({
                            'status': '401 Unauthorized ',
                            'message': 'Password not match'
                        })
        else :
                send_otp_via_email_for_reset(first_data.email)
                return Response({'status' : '401' ,'message' : 'OTP is no longer valid' , 'data' : 'otp wrong' })



class TestPin(APIView):
    def post(self, request):
        email = request.data.get('email')
        print(email)
        pin = request.data.get('pin')
        print(pin)
        data = User.objects.get(email = email)
        if bcrypt.checkpw(pin.encode('utf-8'), data.pin):
            print(True)
        else :
            print(False)
        print(f"{data.pin}")
        return Response({'status': 200})


class TransactionView(APIView):
    def post(self, request):
        try:
            w3 = connect_to_w3()
            token = request.data.get('token')
            to_address = request.data.get('to_address')
            amount = request.data.get('amount')
            pin = request.data.get('pin')
            access_token = AccessToken(token)
            username_from_token = access_token['username']
            data = User.objects.get(username=username_from_token)
            # Check if to_address is a valid address on the Ethereum blockchain.
            if not w3.is_address(to_address):
                return Response({
                    'status': '400 Bad Request',
                    'message': 'Invalid to_address'
                })
            # Convert to_address to a valid checksum address on the Ethereum blockchain
            receiver = w3.to_checksum_address(to_address)

            if not bcrypt.checkpw(pin.encode('utf-8'), data.pin):
                return Response({
                    'status': '401 Unauthorized',
                    'message': 'Invalid PIN'
                })

            contract_address = read_contract_address()
            #Call the open_transaction_factory() function to open and get information about the ABI (Application Binary Interface) of the contract.
            abi, abi2 = open_transaction_factory()
            # Create a contract object on the Ethereum blockchain by passing in the address and ABI
            contract_instance = w3.eth.contract(address=contract_address, abi=abi)
            #Decrypt the private key from the stored data of data
            private_key = decrypt_private_key(w3, data.data, data.pin)
            amount_in_wei = w3.to_wei(amount, 'ether')
            transaction = transaction_json(w3, data.user_address, amount_in_wei)

            if check_fee(w3, data.user_address, amount_in_wei):
                return Response({
                    'status': '400',
                    'message': 'Not enough fee to transaction'
                })
            # Call the createTransaction() function to create and execute transactions on the Ethereum blockchain.
            receipt, success = createTransaction(w3, contract_instance, receiver, private_key, amount_in_wei, transaction)
            hash_block = receipt.blockHash.hex()
            transaction_hash = receipt.transactionHash.hex()

            if success:
                balance = w3.from_wei(w3.eth.get_balance(data.user_address), "ether")
                transaction_address = get_last_transaction(contract_instance)
                history = HistoryModel(user_address=data.user_address, username=data.username, hash_block=hash_block,
                                    contract_address=transaction_address, transaction_hash=transaction_hash)
                history.save()
                return Response({
                    'status': '200 OK',
                    'message': 'Transaction was made successfully',
                    'data': {'balance': balance}
                })
            else:
                return Response({
                    'status': '400',
                    'message': receipt
                })
        except Exception as e:
            return Response({
                'status': '500 Internal Server Error',
                'message': str(e)
            })
        


class PendingView(APIView) :
    def post(self , request) :
        w3 = connect_to_w3()
        token = request.data.get('token')
        access_token = AccessToken(token)
        username_from_token = access_token['username']
        user_address = User.objects.get(username=username_from_token)
        user_add = user_address.user_address
        history = get_pending_transactions(w3, user_add)
        return Response({
            'status': '200 OK',
            'message': 'Successfully retrieved pending transactions',
            'data' : history
            })
    

class HistoryView(APIView) : 
    def post(self, request):
        w3 = connect_to_w3()
        token = request.data.get('token')
        access_token = AccessToken(token)
        username_from_token = access_token['username']
        user = User.objects.get(username=username_from_token)

        actions = ['txlist', 'txlistinternal']  # List of actions

        history = []
        id = 0
        for action in actions:
            params = {
                'module': 'account',
                'action': action,
                'address': user.user_address,
                'startblock': 0,
                'endblock': 99999999,
                "page": 1,
                "offset": 10,
                'sort': 'asc',
                'apikey': config('API_KEY')
            }

            offset = 0
            while True:
                params['offset'] = 10  # Set the offset
                params['page'] = offset + 1  # Set the page number

                data_result = get_data_api(params)
                if not data_result:
                    break  # If the result is empty, break the loop

                for each_result in data_result:
                    id += 1 
                    time = convert_to_time(int(each_result['timeStamp']))
                    amount_wei = int(each_result['value'])
                    amount_eth = w3.from_wei(amount_wei, "ether")
                    amount_eth = Decimal(amount_eth)
                    amount_decimal = "{:.50f}".format(amount_eth).rstrip('0')
                    if user.user_address == w3.to_checksum_address(each_result['to']):
                        amount = f"+{amount_decimal}"
                    else:
                        amount = f"-{amount_decimal}"
                    if each_result['isError'] == "0":
                        valid = True
                    else:
                        valid = False
                    item = {
                        "id" : id , 
                        "timestamp": time,
                        "amount": amount,
                        "valid": valid,
                        "from" : each_result['from'] ,
                        "to": each_result['to']
                    }
                    history.append(item)

                offset += 1

        return Response({
            'status': '200 OK',
            'message': 'Successfully retrieved history',
            'data': history 
        })   
          

class ExecuteView(APIView):
    def post(self, request):
        w3 = connect_to_w3()
        token = request.data.get('token')
        access_token = AccessToken(token)
        username_from_token = access_token['username']
        pin = request.data.get('pin')
        transaction_address = request.data.get('item')
        action = request.data.get('action')
        user = User.objects.get(username=username_from_token)
        user_address = user.user_address
        abi, abi2 = open_transaction_factory()
        private_key = decrypt_private_key(w3, user.data, user.pin)
        send_transaction = transaction_json(w3, user.user_address, 0)

        history = []
        if bcrypt.checkpw(pin.encode('utf-8'), user.pin):
            history, balance = process_transaction(action, user, transaction_address, w3, abi2, private_key, send_transaction ,user_address)

            return Response({
                'status': '200 OK',
                'message': 'Successfully retrieved pending transactions',
                'data': {
                    'history': history,
                    'balance': balance
                }
            })


class AllBlockView(APIView):
    def get(self , request) :
        w3 = connect_to_w3()
        block_chain = []
        unique_block = []
        return_block = []

        blocks = HistoryModel.objects.all()
        for bl in blocks :
            if bl is not None :
                block_chain.append(bl.hash_block) 
                block_chain.append(bl.hash_block_transaction)
            


        for unique in block_chain :
            if unique not in unique_block :
                unique_block.append(unique)
        
        for block in unique_block : 
            block = w3.eth.get_block(block, True)
            block_item = {
                'number' : block.number,
                'hash' : block.hash.hex() ,
                'previous_hash' : block.parentHash.hex() ,
                'nonce' : int(block.nonce.hex(), 16) ,
                'timestamp' : block.timestamp
            }
            return_block.append(block_item)
        return Response({
                'status': '200 OK',
                'message': 'Fetch all blocks successfully ', 
                'data' : return_block
            })

class BlockDetailView(APIView):
    def get(self, request, block_id):
        w3 = connect_to_w3()

        transactions_hash = []
        return_transactions = []
        blocks = HistoryModel.objects.all()

        id = 0 
        # if w3.is_address(block_id):
        
        fetch_block =  w3.eth.get_block(block_id, True)
        all_transaction = fetch_block.transactions
        for db_trans in blocks : 
            transactions_hash.append(db_trans.transaction_hash)
            transactions_hash.append(db_trans.execute_transaction_hash)
        for trans in all_transaction : 
            if trans.hash.hex()  in transactions_hash : 
                id += 1 
                amount = Decimal((w3.from_wei(trans.value, 'ether')))
                amount_decimal = "{:.50f}".format(amount).rstrip('0')
                return_transactions.append({
                        'id' : id ,
                        'from' : trans['from'] ,
                        'to' : trans['to'] , 
                        'hash' : trans.hash.hex() , 
                        'value' : amount_decimal
                        })
                
        return Response({
            'status': '200 OK',
            'message': 'Block detail fetched successfully',
            'data': return_transactions
        })