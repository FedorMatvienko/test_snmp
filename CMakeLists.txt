# Определение библиотек и опций компиляции
cmake_minimum_required( VERSION 3.8.0 )

# Установка стандарта для компилятора, чтобы программа видела стандарт +17
set( CMAKE_CXX_STANDARD 20 )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
# Установка названия проекта
set ( project test_snmp )
project ( ${project} )

add_executable( ${project} main.cpp)
target_link_libraries(${project} netsnmp jsoncpp )