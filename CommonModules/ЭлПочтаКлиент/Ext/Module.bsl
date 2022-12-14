Функция ПисьмоПереслать(Письмо, АдресОтвета) Экспорт
	//Пересылает входящее письмо (параметр Письмо)
	Доступно = 		ТипЗнч(Письмо) 		= Тип("ИнтернетПочтовоеСообщение")
				И	ТипЗнч(АдресОтвета) = Тип("Строка")
				И	ЗначениеЗаполнено(АдресОтвета);
	Если Не Доступно Тогда
		Возврат "ошибка"
	КонецЕсли;
	
	//Получи вложения
	Вложения = Новый СписокЗначений();
	Для Каждого i Из Письмо.Вложения Цикл
		//Исключи из вложений - вложенные почтовые сообщения, не получается пока их обработать корректно
		Если ТипЗнч(i.Данные) = Тип("ИнтернетПочтовоеСообщение") Тогда
			Продолжить;
		КонецЕсли;
		Вложения.Добавить(i.Данные, i.ИмяФайла);	
	КонецЦикла;
	
	//Сформируй из полученного письма тело, включая шапку from,send,to,subject
	Отправитель 	= ?(ТипЗнч(Письмо.Отправитель) = Тип("ИнтернетПочтовыйАдрес"), Письмо.Отправитель.Адрес, Письмо.Отправитель);
	Отправлено		= Письмо.ДатаОтправления;
	Получатели = "";
	Для Каждого i Из Письмо.Получатели Цикл
		Получатели = Получатели + ?(ЗначениеЗаполнено(Получатели), ",", "") + i.Адрес;
	КонецЦикла;
	Тема = Письмо.Тема;
			
	Тело = "";
	Для Каждого i Из Письмо.Тексты Цикл
		Тело = Тело + i.Текст;	
	КонецЦикла; 
		
	ПС = Символы.ПС;
	Тело ="-----------------------------"+ПС+"From: "+Отправитель+ПС+"Sent: "+Отправлено+ПС+"To: "+Получатели+ПС+"Subject: "+Тема+ПС+ПС+Тело;	
	
	Парам = Новый Структура();
	//Парам.Вставить("АдресОтвета", 	АдресОтвета);
	Парам.Вставить("АдресОтвета",				"ekc@luidor.ru");
	Парам.Вставить("Тема",						СтрШаблон("FW:%1", Письмо.Тема));
	Парам.Вставить("Тело",						Тело);
	Парам.Вставить("Вложения", 					Вложения);
	Парам.Вставить("ВходящееПисьмоОснование",	Письмо.ИдентификаторСообщения);
	
	ОткрытьФорму("ОбщаяФорма.ОтправкаПочтовогоСообщения4", Парам);
		
КонецФункции
