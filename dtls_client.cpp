/*
DTLS样例程序
========================
仅供参考，请勿在生产环境中使用!

两种编译方法:
1. 推荐使用make命令编译;
2. 也可使用g++命令手动编译dtls_client.cpp:
    g++ -g -I/usr/include/botan-2 dtls_client.cpp -lbotan-2

注, Ubuntu环境应提前安装依赖的开发工具:
    sudo apt-get install -y botan libbotan-2-dev libbotan-2-doc
    sudo apt-get install -y libssl-dev

调试方法:
步骤1. 进入server子目录, 使用make命令生成测试要用到的私钥及证书, 编译测试服务器程序:
    cd server/
    make
步骤2. 运行测试服务器程序:
    ./server 127.0.0.1:4433
步骤3. 打开另一个终端控制台, 回到客户端代码所在目录, 创建三个目录分别存放CA证书、客户端证书以及客户端私钥;
    cd ..
    mkdir ca-certificates                           # 注: 创建自定义CA证书目录
    cp server/root-ca.pem ca-certificates/          #     复制根证书文件root-ca.pem到自定义CA证书目录
    mkdir client-certificates                       # 注: 创建自定义证书目录
    cp server/client-cert.pem client-certificates/  #     复制证书文件client-cert.pem到自定义证书目录
    mkdir client-private-keys                       # 注: 创建自定义私钥目录
    cp server/client-key.pem client-private-keys/   #     复制私钥文件client-key.pem到自定义私钥目录
目录结构如下图:
├── ca-certificates
│   └── root-ca.pem
├── client-certificates
│   └── client-cert.pem
└── client-private-keys
    └── client-key.pem
步骤4. 编译并执行客户端程序dtls_client:
    make
    ./dtls_client
TODO: 后续考虑将相对路径ca-certificates、client-certificates以及client-private-keys改为系统绝对路径...

其他调试方法: 首先将步骤1生成的server-cert.pem证书和server-key.pem私钥复制到当前目录备用.
使用botan命令创建一个echo服务器, 监听本机UDP 4433端口, 默认协议DTLS 1.2:
    botan tls_server server-cert.pem server-key.pem --port=4433 --type=udp
最后, 启动客户端程序dtls_client
*/

/* POSIX 标准 API */
#include <unistd.h>// using STDIN_FILENO
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>// using sockaddr_storage

/* C++ 标准头文件 */
#include <vector>
#include <cstdio>
using std::printf;
using std::fprintf;
using std::fflush;
using std::putchar;
#include <cstring>
using std::strerror;
#include <cctype>
using std::isprint;
using std::isspace;

/* Botan API ( 使用手册详见 https://botan.randombit.net/manual/tls.html ) */
#include <botan/tls_client.h>
using Botan::TLS::Client;
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_policy.h>
#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/credentials_manager.h>
#include <botan/x509path.h>
using Botan::Path_Validation_Restrictions;
using Botan::Path_Validation_Result;
#include <botan/hex.h>
using Botan::hex_encode;
#include <botan/pkcs8.h>
using Botan::PKCS8::load_key;
#include <botan/data_src.h>
using Botan::DataSource_Stream;


/**
 * @brief Client side implementation of DTLS callback methods
 */
class Client_Side_Implemented_Callbacks: public Botan::TLS::Callbacks { // 备注: 父类 Botan::TLS::Callbacks 是一个抽象接口类, 接口定义位于 botan-2.9.0/src/lib/tls/tls_callbacks.h 头文件.
public:
    /// 回调函数: tls_emit_data(encrypted_data[], size)用于发送密文到任意UDP套接字
    /// (此回调函数不可省略)
    void tls_emit_data(const uint8_t data[], size_t size) override
    {
        if (!m_have_udp_stuffs_registered) {
            return;
        }
        // send data to DTLS server using BSD sockets:
        sendto(m_sockfd, data, size, m_sockflags, (struct sockaddr *) &m_remote_peer_sockaddr, m_sockaddr_len);
    }

    /// 回调函数: tls_record_received(seq_no, plaintext_data[], size)用于取回服务器端的应答数据, 传递给用户, 最终由用户负责应用层逻辑
    /// (此回调函数不可省略)
    void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size)
            override
    {
        printf("Debug: received %u bytes from server\n", (unsigned) size);
        //printf("Debug: seq_no = 0x%llu\n", (unsigned long long) seq_no);
        // 此处将收到的应答直接打印在终端屏幕上
        for (size_t i = 0; i < size; i++) {
            char ch = data[i];
            if (!(isprint(ch) || isspace(ch))) {// 暂时仅支持ASCII字符
                ch = '?';// 其他特殊字符(包括UTF-8或GB2312汉字编码)将被转换为问号显示
            }
            putchar(ch);
        }
        if (size > 0 && '\n' != data[size - 1]) {
            putchar('\n');
        }
    }

    /// 回调函数: tls_alert(alert)用于处理DTLS/TLS协议中的Alert异常状态码
    /// (此回调函数不可省略)
    void tls_alert(Botan::TLS::Alert alert) override
    {
        // handle a DTLS alert received from the DTLS server
        fprintf(stderr, "Debug: Got DTLS Alert: %s\n", alert.type_string().c_str());// 此处仅仅打印了一条警告信息到终端屏幕上

        // TODO: 定制实现完整的DTLS Alert异常分类处理逻辑
        if (alert.type_string().compare("handshake_failure") == 0) {
            return;
        } else if (alert.type_string().compare("close_notify") == 0) {
            fprintf(stderr, "Debug: Server notify us to close DTLS session...\n");// 此处仅仅打印了一条警告信息到终端屏幕上
        }
    }

    /// 回调函数: tls_session_established(session)
    /// (此回调函数不可省略)
    ///
    /// Called when a session is established. Throw an exception to abort
    /// the connection.
    ///
    /// @param session the session descriptor
    ///
    /// @return return false to prevent the session from being cached,
    /// return true to cache the session in the configured session manager
    bool tls_session_established(const Botan::TLS::Session& session) override
    {
        // 打印服务器证书信息
        const std::vector<Botan::X509_Certificate>& certs = session.peer_certs();

        for (size_t i = 0; i != certs.size(); ++i) {
            printf("Certificate %u/%u\n", (unsigned)i + 1, (unsigned)certs.size());
            printf("%s\n", certs[i].to_string().c_str());
            printf("%s\n", certs[i].PEM_encode().c_str());
        }
        printf("Handshake complete, %s using %s\n",
                session.version().to_string().c_str(),
                session.ciphersuite().to_string().c_str());
        if (!session.session_id().empty()) {
            printf("Session ID %s\n", hex_encode(session.session_id()).c_str());
        }
        if (!session.session_ticket().empty()) {
            printf("Session ticket %s\n", hex_encode(session.session_ticket()).c_str());
        }
        return true;
        // 备注: 此处如果返回false则将阻止DTLS会话(需要重新握手).
        // 返回true, 则后续阶段即将开始发送DTLS 1.2 Application Data数据包.
    }

    /// 可选的回调函数: session_activated()
    /// Called when a session is active and can be written to
    void tls_session_activated()
    {
        printf("输入Q加回车主动关闭DTLS信道；\n");
        printf("输入R加回车重新执行握手；\n");
        printf("输入其他字符加回车:等待服务器应答(依赖于特定服务器)；\n");
    }

    /// 回调函数: tls_verify_cert_chain(cert_chain, ocsp, trusted_roots, usage, hostname, policy)用于检查服务器端应答的X509数字证书(证书链)
    ///
    /// Optional callback with default impl: verify cert chain
    ///
    /// Default implementation performs a standard PKIX validation
    /// and initiates network OCSP request for end-entity cert.
    /// Override to provide different behavior.
    ///
    /// Check the certificate chain is valid up to a trusted root, and
    /// optionally (if hostname != "") that the hostname given is
    /// consistent with the leaf certificate.
    ///
    /// This function should throw an exception derived from
    /// std::exception with an informative what() result if the
    /// certificate chain cannot be verified.
    ///
    /// @param cert_chain specifies a certificate chain leading to a trusted root CA certificate.
    /// @param ocsp_responses the server may have provided some
    /// @param trusted_roots the list of trusted certificates
    /// @param usage what this cert chain is being used for
    ///        Usage_Type::TLS_SERVER_AUTH for server chains,
    ///        Usage_Type::TLS_CLIENT_AUTH for client chains,
    ///        Usage_Type::UNSPECIFIED for other uses
    /// @param hostname when authenticating a server, this is the hostname
    ///        the client requested (eg via SNI). When authenticating a client,
    ///        this is the server name the client is authenticating to.
    ///        Empty in other cases or if no hostname was used.
    /// @param policy the TLS policy associated with the session being authenticated
    ///        using the certificate chain
    void tls_verify_cert_chain(
            const std::vector<Botan::X509_Certificate>& cert_chain,/// specifies a certificate chain leading to a trusted root CA certificate.
            const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp,///
            const std::vector<Botan::Certificate_Store*>& trusted_roots,///the list of trusted certificates
            Botan::Usage_Type usage,/// the usage that the cert chain is being used for
            const std::string& hostname,/// the server name which the client is authenticating to
            const Botan::TLS::Policy& policy) override
    {
        if (cert_chain.empty()) {
            throw Botan::Invalid_Argument("Certificate chain was empty");
        }

        Botan::Path_Validation_Restrictions restrictions(policy.require_cert_revocation_info(), policy.minimum_signature_strength());

        auto ocsp_timeout = std::chrono::milliseconds(1000);

        // 此处调用 Botan::x509_path_validate()检查服务器证书
        Botan::Path_Validation_Result result =
            Botan::x509_path_validate(cert_chain, restrictions, trusted_roots, hostname, usage, std::chrono::system_clock::now(), ocsp_timeout, ocsp);

        printf("Debug: Certificate validation status: %s\n", result.result_string().c_str());
        if (result.successful_validation()) {
            auto status = result.all_statuses();

            if (status.size() > 0 && status[0].count(Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD)) {
                printf("Valid OCSP response for this server\n");
            }
        }
    }

    /* 以下添加自定义接口函数, 以及其相应的私有成员变量 */

    /// 注册 UDP 相关信息
    void register_udp_stuffs(
            int sockfd,/// UDP 端口号
            int udp_sock_flags,
            const struct sockaddr_storage& server_sockaddr,
            size_t server_sockaddr_size)
    {
        m_sockfd = sockfd;
        m_sockflags = udp_sock_flags;
        if (server_sockaddr_size > sizeof(m_remote_peer_sockaddr)) {
            server_sockaddr_size = sizeof(m_remote_peer_sockaddr);
        }
        memcpy(&m_remote_peer_sockaddr, &server_sockaddr, server_sockaddr_size);
        m_sockaddr_len = (AF_INET6 == server_sockaddr.ss_family)?
                sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
        m_have_udp_stuffs_registered = true;
    }
private:
    int m_sockflags = 0;
private:
    int m_sockfd = -1;
private:
    size_t m_sockaddr_len = 0;
private:
    struct sockaddr_storage m_remote_peer_sockaddr = { .ss_family = AF_INET };
private:
    bool m_have_udp_stuffs_registered = false;
};


/**
 * @brief Credentials storage for the DTLS client (or TLS client).
 *
 * It returns a list of trusted CA certificates from a local directory.
 *
 * @see Botan::Credentials_Manager 的使用手册 https://botan.randombit.net/manual/credentials_manager.html
 */
class Client_Side_Credentials_Manager: public Botan::Credentials_Manager {// 备注: 父类 Botan::Credentials_Manager 定义于 botan-2.9.0/src/lib/tls/credentials_manager.h 头文件.
public:
    /**
     * @brief 内部类 CredentialNode 用于存储 Client 侧私钥.
     */
    class CredentialNode {
    public:
        std::vector<Botan::X509_Certificate> certchain;
    public:
        std::shared_ptr<Botan::Private_Key> privkey;
    };
private:
    std::vector<CredentialNode> m_creds;
public:
    /// 自定义接口函数: 重置客户端证书和私钥
    void reset_client_credential_node(const CredentialNode& certchain_privkey_bundle_node)
    {
        m_creds.clear();
        m_creds.push_back(certchain_privkey_bundle_node);
    }
public:
    /// 回调函数: private_key_for()按数字证书查询并取出对应的客户端私钥
    Botan::Private_Key* private_key_for(
            const Botan::X509_Certificate& cert,
            const std::string& type,
            const std::string& context) override
    {
        // when returning a chain in cert_chain(), return the private key
        // associated with the leaf certificate here
        for (auto const& i : m_creds) {
            if (i.certchain[0] == cert) {
                return i.privkey.get();
            }
        }

        return nullptr;
    }

private:
    std::vector<Botan::Certificate_Store*> m_trusted_ca_list;
private:
    /// 私有成员函数, 从私有目录查找根证书文件并初始化证书链
    void init_trusted_certificate_authorities(void)
    {
        // 此处假定:
        // 1. 已将CA自签根证书文件放在当前路径的ca-certificates子目录内, 程序运行时读取目录内的证书文件.
        // 2. 已将client-cert证书文件放在当前路径的client-certificates子目录内, 程序运行时读取目录内的证书文件.
        // TODO: 后续考虑将相对路径改为系统绝对路径
        m_trusted_ca_list.clear();
        m_trusted_ca_list.push_back(new Botan::Certificate_Store_In_Memory("ca-certificates"));
        m_trusted_ca_list.push_back(new Botan::Certificate_Store_In_Memory("client-certificates"));
        // 由于我们只使用企业内部颁发的证书, 所以不需要去搜索Unix系统常用的公共互联网证书目录(例如"/etc/ssl/certs"和"/usr/share/ca-certificates")
        // 如需与企业外其他主机通讯, 可以根据具体情况在上述两个文件夹中添加通信双方都认可的根证书及二级证书
    }
public:
    std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
            const std::string& type,
            const std::string& context) override
    {
        // return a list of certificates of CAs we trust for DTLS server certificates,
        if (m_trusted_ca_list.size() > 0) {
            return m_trusted_ca_list;
        }
        init_trusted_certificate_authorities();
        return m_trusted_ca_list;
    }
public:
    std::vector<Botan::X509_Certificate> cert_chain(
            const std::vector<std::string>& cert_key_types,
            const std::string& type,
            const std::string& context) override
    {
        // when using DTLS client authentication (optional), return
        // a certificate chain being sent to the DTLS server,
        // else an empty list
        if (m_creds.empty()) {
            return std::vector<Botan::X509_Certificate>();
            // 返回空的链表 std::vector<X509_Certificate>()时 DTLS/TLS 会话无法进行双向身份认证, 只能对服务器进行单向身份认证...
        }

        /* 客户端数字证书, 使客户端程序支持 DTLS/TLS 双向身份认证. */
        if (type.compare("tls-client") == 0 && m_creds.size() > 0) {
            // 客户端如果只有一个证书文件
            if (m_creds.size() == 1) {
                return m_creds[0].certchain;
            }
            // 客户端如果只有一个证书文件, 还要借助context文本匹配, 证书中附带的字段
        }
        return std::vector<Botan::X509_Certificate>();
        // 以上为客户端证书链查找逻辑

        // 以下为服务器端证书链查找逻辑: 服务器端的证书管理器通常是根据主机域名字段从多个证书中选择相匹配的一个服务器证书
        // if (type.compare("tls-server") == 0) {
        //     const std::string& hostname = context;
        //     for(auto const& node : m_creds) {
        //         if(std::find(cert_key_types.begin(), cert_key_types.end(), node.privkey->algo_name()) == cert_key_types.end()) {
        //             continue;
        //         }
        //         if(hostname != "" && !node.certchain[0].matches_dns_name(hostname)) {
        //             continue;
        //         }
        //         return node.certchain;
        //     }
        // }
    }
};


static int compare_sockaddr(const struct sockaddr_storage *peer, const struct sockaddr_storage *expected);/// 比较两组网络地址端口号是否相等, 相等时返回0, 不相等时返回非零整数


int main()
{
    /* 准备UDP socket文件描述符 */
    int af_inetx;
    int sockfd;// socket文件描述符(socket file descriptor)
    const int udp_sock_type = SOCK_DGRAM | SOCK_CLOEXEC;
    const int udp_sock_flags = 0;

    af_inetx = AF_INET;// AF_INET 对应 IPv4， AF_INET6 对应 IPv6
    if ((sockfd = socket(af_inetx, udp_sock_type, 0)) < 0) {
        printf("Error: Can not create a UDP socket.\n");
        return 1;
    }

    const char *server_ip_str;// IPv4 or IPv6 address string
    uint32_t server_udp_port;

    server_ip_str = "127.0.0.1";// 注: 默认在本机执行client/server调试
    server_udp_port = 4433;

    /* 制作server_sockaddr结构体, 用于指定服务器端的IP地址和UDP端口号 */
    struct sockaddr_storage server_sockaddr;
    socklen_t server_sockaddr_size = 0;

    memset((void*) &server_sockaddr, 0x00, sizeof(server_sockaddr));
    server_sockaddr.ss_family = af_inetx;
    struct sockaddr_in *ipv4;
    struct sockaddr_in6 *ipv6;
    switch (af_inetx) {
    case AF_INET:
        ipv4 = (struct sockaddr_in *) &server_sockaddr;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(server_udp_port);
        if (inet_pton(AF_INET, server_ip_str, &ipv4->sin_addr) < 1) {
            printf("Error: Unable to parse IP address string %s\n",
                    server_ip_str);
            return 1;
        }
        server_sockaddr_size = sizeof(struct sockaddr_in);
        break;

    case AF_INET6:
        ipv6 = (struct sockaddr_in6 *) &server_sockaddr;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(server_udp_port);
        if (inet_pton(AF_INET6, server_ip_str, &ipv6->sin6_addr) < 1) {
            printf("Error: Unable to parse IPv6 address string %s\n",
                    server_ip_str);
            return 1;
        }
        server_sockaddr_size = sizeof(struct sockaddr_in6);

    default:// Never happen
        break;
    }

    /* 准备各种材料, 用于创建 Client 对象实例 */
    Botan::AutoSeeded_RNG rng;
    Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
    Botan::TLS::Default_Policy policy;

    printf("DTLS default cipher suite list:\n");
    for (uint16_t id : policy.ciphersuite_list(Botan::TLS::Protocol_Version::DTLS_V12, false)) {
        // 打印调试信息: 密码套件列表
        printf("\t0x%04X: %s\n", (int) id, Botan::TLS::Ciphersuite::by_id(id).to_string().c_str());
    }

    Client_Side_Credentials_Manager creds;// 客户端证书管理者, 其中回调函数 cert_chain()提供客户端自身证书链; 回调函数 private_key_for()提供客户端自身私钥key值;
    Client_Side_Implemented_Callbacks client_callback_handler;// 客户端自定义的回调函数, 其中: 回调函数 tls_emit_data()负责向UDP套接字发送密文数据, 回调函数 tls_alert() 处理DTLS会话中捕获的Alert异常...
    Client_Side_Credentials_Manager::CredentialNode node;
    bool all_client_pem_files_exist = false;
    /* TODO: 检查客户端证书及私钥文件是否存在。如不存在则不加载客户端证书然后DTLS过程只进行单向身份认证。*/
    if (1) {
        all_client_pem_files_exist = true;
    }
    if (all_client_pem_files_exist) {
        // 此处共用主程序中的随机数发生器 Botan::RandomNumberGenerator& rng;

        Botan::DataSource_Stream keyfile("client-private-keys/client-key.pem");// FIXME: 需要处理文件不存在的异常情况
        std::string passphrase = "";

        try {
            Botan::Private_Key *keyobj;
            keyobj = Botan::PKCS8::load_key(keyfile, rng, passphrase);
            node.privkey.reset(keyobj);
        } catch (std::exception& e1) {
        }

        Botan::DataSource_Stream certfile("client-certificates/client-cert.pem");// FIXME: 需要处理文件不存在的异常情况
        while(!certfile.end_of_data()) {
            try {
                node.certchain.push_back(Botan::X509_Certificate(certfile));
            } catch (std::exception& e2) {
            }
        }
    }
    creds.reset_client_credential_node(node);

    client_callback_handler.register_udp_stuffs(// 将UDP套接字相关信息提供给 client_callback_handler
            sockfd, udp_sock_flags, server_sockaddr, server_sockaddr_size);

    const char *server_cert_common_name = "";
    // 服务器程序所使用的数字证书中CN(Common Name)字段的值应与此处 server_cert_common_name 字符串值一致
    // 当服务器同时拥有多个不同数字证书时, 服务器应根据CN(Common Name)字段选择相应的证书.
    // 服务器端若没有相应证书, 直接向客户端回一条DTLS Alert提示信息: Level=0x01(Warning), Description=0x70(Unrecognized Name)
    // 然后继续询问客户端是否接受与 server_cert_common_name 不同服务器证书.
    server_cert_common_name = "test_server";

    /* 创建 Client 对象实例 */
    Client client(client_callback_handler, session_mgr, creds, policy, rng,
            Botan::TLS::Server_Information(server_cert_common_name, server_udp_port),
            Botan::TLS::Protocol_Version::DTLS_V12);

    bool is_session_first_time_established = true;
    uint8_t recvbuf[4 * 1024];
    const size_t recvbufsize = sizeof(recvbuf);

    while (!client.is_closed()) try {
        fd_set allfds;
        int maxfd;

        FD_ZERO(&allfds);
        FD_SET(sockfd, &allfds);
        maxfd = sockfd;

        if (client.is_active()) {
            FD_SET(STDIN_FILENO, &allfds);
            maxfd = (sockfd > STDIN_FILENO)? sockfd : STDIN_FILENO;
        }

        struct timeval timeout = { 1, 0 };

        // 开始IO轮询
        select(maxfd + 1, &allfds, NULL, NULL, &timeout);

        if (FD_ISSET(sockfd, &allfds)) {
            union {
                struct sockaddr ipvx;
                struct sockaddr_in ipv4;
                struct sockaddr_in6 ipv6;
                struct sockaddr_storage storage;
            } remote_sockaddr;
            socklen_t sockaddr_len = sizeof(remote_sockaddr);
            ssize_t got;

            got = recvfrom(sockfd, recvbuf, recvbufsize, udp_sock_flags, &remote_sockaddr.ipvx, &sockaddr_len);
            if (got == 0) {
                printf("Warning! Got EOF from UDP socket\n");
                break;
            } else if (got == -1) {
                fprintf(stderr, "Socket error: %s\n", strerror(errno));
                continue;
            }

            // 检查收到的UDP应答包端口号及IP地址与预期是否一致(防御有敌意的端口扫描器向当前UDP端口号发送干扰包)
            if (compare_sockaddr(&remote_sockaddr.storage, &server_sockaddr) == 0) {
                client.received_data(recvbuf, got);
            } else {
                fprintf(stderr, "DEBUG: received a unexpected UDP packet from a different server!\n");
                // UDP应答包中的IP地址及端口号与客户端请求的服务器地址不一致, 直接丢弃该包
            }
        }

        if (FD_ISSET(STDIN_FILENO, &allfds)) {
            uint8_t filebuf[1024] = { 0 };
            ssize_t got;

            got = read(STDIN_FILENO, filebuf, sizeof(filebuf));
            if (0 == got) {
                printf("No more bytes from stdin. Exiting...\n");
                client.close();
                break;
            } else if (got < 0) {
                fprintf(stderr, "Error: %s\n", strerror(errno));
                continue;
            }

            // 终端输入特殊命令控制退出和进行重新握手
            // -----------------------------------
            // 1、"Q\n"命令主动关闭DTLS信道；
            // 2、"R\n"命令重新执行握手；
            if (got == 2 && filebuf[1] == '\n') {
                char cmd = filebuf[0];
                if (cmd == 'R') {
                    printf("Client initiated renegotiation\n");
                    client.renegotiate(true);
                    continue;
                } else if (cmd == 'Q') {
                    printf("Client initiated close\n");
                    client.close();
                    break;
                }
            }

            client.send(filebuf, got);
        }

        if (client.timeout_check()) {
            fprintf(stderr, "Warning: Timeout detected!\n");
        }
    }
    catch (Botan::TLS::TLS_Exception exception) {
        fprintf(stderr, "Error: Failed to continue DTLS session...\n");
        fprintf(stderr, "what hanppened = %s\n", exception.what());
    }
    close(sockfd);
}

/// 比较两组网络地址端口号是否相等, 相等时返回0, 不相等时返回非零整数
static int compare_sockaddr(const struct sockaddr_storage *peer, const struct sockaddr_storage *expected)
{
    size_t len; // IPv4/IPv6地址长度分别为4和16字节
    int peer_port;
    int expected_port;
    void *peer_ipvx_addr;
    void *expected_ipvx_addr;
    const struct sockaddr_in *peer_ipv4 = (const struct sockaddr_in *)peer;
    const struct sockaddr_in6 *peer_ipv6 = (const struct sockaddr_in6 *)peer;
    const struct sockaddr_in *expected_ipv4 = (const struct sockaddr_in *)expected;
    const struct sockaddr_in6 *expected_ipv6 = (const struct sockaddr_in6 *)expected;

    if (peer->ss_family != expected->ss_family) {
        return (peer->ss_family - expected->ss_family);
    }

    switch (peer->ss_family) {
    case AF_INET:
        expected_ipvx_addr = (void*)&(expected_ipv4->sin_addr);
        expected_port = ntohs(expected_ipv4->sin_port);
        peer_ipvx_addr = (void*)&(peer_ipv4->sin_addr);
        peer_port = ntohs(peer_ipv4->sin_port);
        len = sizeof(peer_ipv4->sin_addr);
        break;

    case AF_INET6:
        expected_ipvx_addr = (void*)&(expected_ipv6->sin6_addr);
        expected_port = ntohs(expected_ipv6->sin6_port);
        peer_ipvx_addr = (void*)&(peer_ipv6->sin6_addr);
        peer_port = ntohs(peer_ipv6->sin6_port);
        len = sizeof(peer_ipv6->sin6_addr);
        break;

    default: // Should not happen
        return memcmp(peer, expected, sizeof(struct sockaddr_storage));
    }

    if (peer_port != expected_port) {
        return (peer_port - expected_port);
    }

    return memcmp(peer_ipvx_addr, expected_ipvx_addr, len);
}
