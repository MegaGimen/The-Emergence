from pyngrok import ngrok
ngrok.set_auth_token('2cLU8IUMb53InLwIZO59krzs7Sv_7jhmAoBkNQTNwPqoXwQo9')
def forward_ngrok(port):
    global http_tunnel
    http_tunnel=ngrok.connect(port)
    return http_tunnel.public_url
print(forward_ngrok(1314))