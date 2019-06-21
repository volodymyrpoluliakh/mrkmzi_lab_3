cmake_minimum_required(VERSION 2.8)

project(el_gamal)

add_executable(${PROJECT_NAME}
    main.cpp
    el_gamal.hpp
    el_gamal.cpp
    )

#target_include_directories(${})
#
target_link_libraries(${PROJECT_NAME} gmp.a boost_program_options.a libstdc++.a)


