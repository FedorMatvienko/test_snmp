#include "main.hpp"
void read_json( string path, vector<DevicesSnmp> & devices )
{
    //Параметры устройств
    vector<string> oids;
    string url;
    uint64_t version;
    string community;
    uint64_t timeout;

    Json::Value config;
    Json::Reader reader;
    std::ifstream input_file( path );

    //Превращение текстового файла в файл конфигурации
    input_file >> config;

    //Разбор файла
    if ( config["devices"].empty() )
    {
        cout << "devices: Нет данных по устройствам для чтения" << endl;
        return;
    }
    cout << "devices: Количество устройств по которым получены данные: " << config["devices"].size() << endl;
    for ( auto & d: config["devices"] )
    {
        //ip адрес устройства
        if ( d["url"].empty() )
        {
            cout << "url: Нет данных" << endl;
            continue;
        }
        url = d["url"].asString();

        //Версия устройства
        if ( d["version"].empty() )
        {
            cout << "version: Нет данных" << endl;
            continue;
        }
        version = d["version"].asUInt64();
        
        //открытый или закрытый
        if ( d["community"].empty() )
        {
            cout << "community: Нет данных" << endl;
            continue;
        }
        community = d["community"].asString();

        //Задержка
        if ( d["timeout"].empty() )
        {
            cout << "timeout: Нет данных" << endl;
            continue;
        }
        timeout = d["timeout"].asUInt64();

        if ( d["params"].empty() )
        {
            cout << "params: Нет данных по параметрам для чтения" << endl;
            continue;
        }
        cout << "params: Количество параметров на устройстве по которым получены данные: " << d["params"].size() << endl;
        for ( auto & p: d["params"] )
        {
            if ( p["oid"].empty() )
            {
                cout << "oid: Нет данных" << endl;
                continue;
            }
            oids.push_back(p["oid"].asString());
        }
        devices.push_back(DevicesSnmp(oids,url,version,community,timeout));
    }
}
bool has_open_quotes(const char *s)
{
    char q{};
    for (; *s; ++s)
    {
        auto c = *s;
        if (c == '\'' || c == '"')
        {
            if (!q)
                q = c;
            else if (q == c)
                q = {};
        }
    }
    if ( q != '\0' )
    {
        cout << "has_open_quotes: Cтрока не удовлетворяет условию" << endl;
    }
    return q != '\0';
}
void snmp::session_snmp( DevicesSnmp d )
{
//Переменные для сессии
    struct snmp_session session = {};
    struct snmp_session *ss = nullptr;

    //Переменные для данных
    oid anOID[MAX_OID_LEN] = {0};
    size_t anOID_len = MAX_OID_LEN;
    int status = 0;
    const size_t bSize = 4096;
    char buf [ bSize ] = {0};
    int rc = 0;

    //Шаг №1 Инициализация сессии
    snmp_sess_init( &session );

    // Получение версии SNMP
    std::cout << "Версия SNMP:\t\t    " << netsnmp_get_version() << std::endl;

    //Шаг №2 Установка атрибутов сессии
    session.version = d.version == 2 ? SNMP_VERSION_2c : SNMP_VERSION_1;
    session.peername = const_cast<char*>( d.url.c_str( ) );
    //Перепись строки типа char в тип u_char
    size_t size = d.community.size( );
    session.community = new u_char[size+1];
    for ( size_t i = 0; i < size; ++i )
    {
        session.community[i] = ( u_char )d.community[i];
    }
    session.community[size] = '\0';
    session.community_len = size;
    session.timeout = static_cast<int32_t>(d.timeout) * 1000l;	//	в микросекунды

    //Шаг №3 Открытие сессии
    ss = snmp_open( &session );

    //Шаг №4 Проверка открытия сеанса
    if ( !ss )
    {
        cout << "snmp_open:\t\t    Сессия не открылась " << ss << endl;
        delete []session.community;
        return;
    }
    else
    {
        cout << "snmp_open:\t\t    Сессия открылась " << ss << endl;
    }

    //Шаг №5 Бесконечный цикл обработки
    while ( true )
    {
        //Шаг №5.1 Опросить все параметры
        for ( auto & p: d.oids )
        {
            //Переменные для сессии
            netsnmp_pdu *pdu = nullptr;
            netsnmp_pdu *response = nullptr;
            netsnmp_variable_list *vars = nullptr;
            //№1 Создание PDU для данных, для нашего запроса
            pdu = snmp_pdu_create( SNMP_MSG_GET );
            if ( !pdu )
            {
                cout << "snmp_pdu_create:\t    pdu( )" << pdu << " не сформирован" << endl;
                continue;
            }
            else
            {
                cout << "snmp_pdu_create:\t    pdu(" << pdu << ") сформирован" << endl;
            }
            //№2 Запись разложенного oid в ячейку anOID и его длины в anOID_len
            if ( has_open_quotes( p.c_str() ) || !read_objid( p.c_str( ), anOID, &anOID_len) )
            {
                cout << "has_open_quotes/read_objid: Не удалось проаназировать строку" << endl;
                continue;
            }
            else
            {
                string soid;
                for ( size_t i = 0; i < anOID_len; ++i )
                {
                    soid+=".";
                    soid+=std::to_string(anOID[i]);
                }
                cout << "has_open_quotes/read_objid: Удалось проаназировать строку(" << soid.c_str() << ")" << endl;
            }
            //№3 Добавление нулевого значения в pdu
            snmp_add_null_var( pdu, anOID, anOID_len );

            //№4 Получение статуса и ответа
            mutQueue.lock( );
            status = snmp_synch_response( ss, pdu, &response );
            mutQueue.unlock( );
            //№5 Если запрос выполнен с ошибкой, то перейти к опросу следующего параметра из списка
            if ( status == STAT_SUCCESS && response != nullptr && response->errstat == SNMP_ERR_NOERROR )
            {
                cout << "snmp_synch_response:\t    Ответ получен, status(" << static_cast<int>(status) << ") ,response(" << response << ")"<< endl;
            }
            else
            {
                snmp_sess_perror("snmp_synch_response",ss);
                cout << "snmp_synch_response:\t    Ответ не получен, status(" << static_cast<int>(status) << ") ,response(" << response << ")"<< endl;
                continue;
            }

            //Установка начального значения для vars
            vars = response->variables;

            //Получение результата
            //В случае ошибки функция возвращает -1, а в случае успеха - количество записанных символов, не считая терминирующего 0
            rc = snprint_value ( buf, bSize, anOID, anOID_len, vars );

            if ( rc < 0 )
            {
                cout << "snprint_value:\t\t    Результат не разложен" << endl;
                snmp_free_pdu( response );
                continue;
            }
            else
            {
                cout << "snprint_value:\t\t    Результат разложен(" << buf << ")" << endl;
            }
            snmp_free_pdu( response );
            cout << endl;
        }
        this_thread::sleep_for( chrono::seconds( 1 ) );
    }
}
int main()
{
    vector<DevicesSnmp> DeviceList;
    filesystem::path currentPath = std::filesystem::current_path();
    string path = "config";
    currentPath /= path;

    read_json( currentPath , DeviceList );

    //Печать данных по устройствам
    for ( auto & d: DeviceList )
    {
        cout << "      url: " << d.url << endl;
        cout << "  version: " << d.version << endl;
        cout << "community: " << d.community << endl;
        cout << "  timeout: " << d.timeout << endl;
        for ( auto & p: d.oids )
        {
            cout << "      oid: " << p << endl;
        }
        cout << endl;
        
    }
    for ( auto & d: DeviceList )
    {
        thread Snmp ( &snmp::session_snmp, d );
        Snmp.detach();
    }

    // 8. Выполнить бесконечный цикл ожидания
    while ( true ) {sleep (600); }
    cout << "Программа завершила работу" << endl;
    return 0;
}