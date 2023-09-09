classe NatTable:
    guarda uma lista de entradas na tablela, traduz resposta do server

classe NatEntry:
    uma entrada na tabela, guarda uma relação:
        ip de entrada, porta de entrada -> ip de destino, porta de destino, protocolo

        a porta de destino vem pronta do host, pois é definida pelo próprio comando que o ranas passou:
            iperf -c IP      -p PORT
            iperf -c 8.8.8.8 -p 8888

pktManager:
    muito chato verificar qual protocolo o cara usa para depois acessar (TCP ou UDP), essa classe cuida disso.
    também gera entradas na tabela dado um pkt, e verifica se há uma entrada válida na tabela dada uma resposta do servidor

acredito que o erro esteja na própria função example ou em algum uso errado do scapy