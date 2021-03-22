
#### Client credentials

http://localhost:9096/token?grant_type=client_credentials&client_id=anything&client_secret=42&scope=read


#### PKCE login

http://localhost:9096/authorize?response_type=code&client_id=anything&redirect_uri=http://localhost:9096&scope=read&state=DAFFY&code_challenge_method=S256&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8=

