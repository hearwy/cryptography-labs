# Зависимости

  * Python > 3.10
    
  * Библиотеки:
    
      * cryptography
      * Pillow
      * numpy
      * matplotlib
      * scipy
      * scikit-image
        
   * Установка зависимостей
     
     ```python 
        pip install -r requirements.txt
      ```
      
# Команды запуска    

  ```python 
     python main.py
  ```

# Параметры 

  ```python

    SOURCE_IMAGE = "imgs/gto.png"       # Исходное изображение
    COVER_IMAGE = "imgs/cover.png"      # Копия исходного изображения по структуре проекта
    PASSWORD = "ggwp"                   # Пароль для шифрования
    MAIN_FILL_RATIO = 0.10              # Уровень заполнения контейнера (10%)
    PAYLOAD_LEVELS = (0.01, 0.10)       # Уровни заполнения для сравнения влияния объёма (1% и 10%)

  ```

# Пример обычного LSB

  ```python 
      from src.lsb import embed_lsb_plain

      embed_lsb_plain(
        cover_path="imgs/cover.png",
        stego_path="imgs/stego_plain.png",
        message="хрумки",
      )
  ```

# Пример гибридного режима

  ```python 
      from src.lsb import embed_lsb_encrypted, embed_lsb_random

      #Зашифрованное последовательное встраивание
      embed_lsb_encrypted(
          cover_path="imgs/cover.png",
          stego_path="imgs/stego_encrypted.png",
          message="хрумки",
          password="ggwp",
      )

      #Зашифрованное псевдослучайное встраивание
      embed_lsb_random(
          cover_path="imgs/cover.png",
          stego_path="imgs/stego_random.png",
          message="хрумки",
          password="ggwp",
      )
  ```

# Пример извлечения и расшифрования

  ```python 
      from src.lsb import (
          extract_lsb_encrypted,
          extract_lsb_plain,
          extract_lsb_random,
      )

      # Извлечение открытого сообщения
      plain_msg = extract_lsb_plain("imgs/stego_plain.png")

      # Извлечение и расшифрование (последовательный режим)
      decrypted_msg = extract_lsb_encrypted(
          stego_path="imgs/stego_encrypted.png",
          password="ggwp",
      )

      # Извлечение и расшифрование (псевдослучайный режим)
      decrypted_random_msg = extract_lsb_random(
          stego_path="imgs/stego_random.png",
          password="ggwp",
      )
  ```
