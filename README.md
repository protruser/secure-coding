# Secure Coding

## Tiny Secondhand Shopping Platform.

You should add some functions and complete the security requirements.

## requirements

if you don't have a miniconda(or anaconda), you can install it on this url. - https://docs.anaconda.com/free/miniconda/index.html

```
git clone https://github.com/protruser/secure-coding.git
conda env create -f enviroments.yaml
```

## usage

run the server process.

```
python app.py
```

if you want to test on external machine, you can utilize the ngrok to forwarding the url.
```
# optional
sudo snap install ngrok
ngrok http 5000
```

## Additional Function
-  비밀번호 변경 로직
-  사용자 조회 기능 (상품 정보에서 확인 가능)
-  마이페이지 기능 (소개글 빛 비밀번호 업데이트)
-  상품 등록 기능 (이미지 파일 업로드 가능) 
-  등록된 상품 관리 기능 (마이페이지에서 확인 가능)
-  상품 조회 기능 (dashboard에서 제목을 통해 조회 가능)
-  1대1 채팅 기능 (쪽지로 구현)
-  불량 상품 삭제 기능 (관리자 페이지)
-  불량 유저 휴면 기능 (관리자 페이지)
-  유저들 간의 송금 기능 (프로필에서 잔액 충전, 상품 페이지에서 송금 가능)
-  관리자 플랫폼 관리 (관리자 페이지)

UI는 많이 별롭니다..
