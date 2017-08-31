################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/KAT.c \
../src/NTRUEncrypt.c \
../src/encrypt.c \
../src/kem.c \
../src/packing.c \
../src/param.c \
../src/test.c 

OBJS += \
./src/KAT.o \
./src/NTRUEncrypt.o \
./src/encrypt.o \
./src/kem.o \
./src/packing.o \
./src/param.o \
./src/test.o 

C_DEPS += \
./src/KAT.d \
./src/NTRUEncrypt.d \
./src/encrypt.d \
./src/kem.d \
./src/packing.d \
./src/param.d \
./src/test.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


