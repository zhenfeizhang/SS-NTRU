################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/poly/DSG.c \
../src/poly/misc.c \
../src/poly/ntt.c \
../src/poly/poly_algo.c \
../src/poly/poly_gen.c 

OBJS += \
./src/poly/DSG.o \
./src/poly/misc.o \
./src/poly/ntt.o \
./src/poly/poly_algo.o \
./src/poly/poly_gen.o 

C_DEPS += \
./src/poly/DSG.d \
./src/poly/misc.d \
./src/poly/ntt.d \
./src/poly/poly_algo.d \
./src/poly/poly_gen.d 


# Each subdirectory must supply rules for building sources it contributes
src/poly/%.o: ../src/poly/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


