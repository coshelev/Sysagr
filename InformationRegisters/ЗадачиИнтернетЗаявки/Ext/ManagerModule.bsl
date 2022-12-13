﻿Функция Добавить(Телефон, ДатаЗакрытия='00010101000000', Исполнитель="", Инициатор="", Комментарий="", ДатаПостановки = '00010101000000', Сигнатура = "", ВыполнитьАвтозвонок = Ложь) Экспорт
	
	Доступно = 		ТипЗнч(Телефон) 		= Тип("Строка") 
	            И 	ТипЗнч(ДатаЗакрытия) 	= Тип("Дата") 
				И 	ЗначениеЗаполнено(Телефон)      
				И	СтрДлина(Телефон) > 9;
		Если Не Доступно Тогда
			ЗаписьЖурналаРегистрации("Добавить", УровеньЖурналаРегистрации.Ошибка,, СтрШаблон("Телефон = %1, ДатаЗакрытия = %2", Телефон, ДатаЗакрытия), "ошибка входных параметров");
		Возврат Ложь;
	КонецЕсли;
	
	НЗ = РегистрыСведений.ЗадачиИнтернетЗаявки.СоздатьМенеджерЗаписи();
	НЗ.Телефон 			= Телефон;
	НЗ.ДатаЗакрытия 	= ДатаЗакрытия;
	НЗ.Прочитать();
	Если НЗ.Выбран() Тогда
		ЗаписьЖурналаРегистрации("Добавить()", УровеньЖурналаРегистрации.Ошибка, , СтрШаблон("Телефон = %1, ДатаЗакрытия = %2", Телефон, ДатаЗакрытия), "Запись с указанными измерениями существует");
		Возврат Ложь;
	КонецЕсли; 
	
	НЗ.Телефон 				= Телефон;
	НЗ.ДатаЗакрытия 		= ДатаЗакрытия;
	НЗ.Исполнитель 			= Исполнитель;
	НЗ.Инициатор 			= Инициатор;
	НЗ.Комментарий 			= Комментарий;
	НЗ.ДатаПостановки		= ДатаПостановки;
	НЗ.Сигнатура			= Сигнатура;
	НЗ.ВыполнитьАвтозвонок 	= ВыполнитьАвтозвонок;
	Попытка
		НЗ.Записать();
		Возврат Истина;
	Исключение
		ЗаписьЖурналаРегистрации("Добавить()", УровеньЖурналаРегистрации.Ошибка, , СтрШаблон("Телефон = %1, ДатаЗакрытия = %2", Телефон, ДатаЗакрытия), ПодробноеПредставлениеОшибки(ИнформацияОбОшибке()));
		Возврат Ложь;
	КонецПопытки
КонецФункции

Функция	НайдиИЗаблокируйПервуюОткрытуюЗадачу_ДляВыполненияЗвонка(Исполнитель) Экспорт
	//возвращает телефон внешнего абонента открытой задачи по интернет-заявке и сигнатуру интернет-заявки. 
	//Одна задача среди открытых выбирается по FIFO 
	//признак задачи, для которой нужен автозвонок - слово "АВТОЗВОНОК" в комментарии.
		
	// Входные параметры:
	//	Исполнитель - номер телефона оператора КЦ, для которого подбирается открытая задача
	
	Результат = Новый Структура();
	Результат.Вставить("Телефон",	"");
	Результат.Вставить("Сигнатура",	"");
	Результат.Вставить("Сайт",		"");

	ЗначениеПоУмолчанию = Результат;

	Доступно = 		ТипЗнч(Исполнитель) = Тип("Строка")
				И 	СтрДлина(Исполнитель)=4;
	
	Если Не Доступно Тогда
		ЗаписьЖурналаРегистрации("НайдиИЗаблокируйПервуюОткрытуюЗадачу", УровеньЖурналаРегистрации.Ошибка, , СтрШаблон("Исполнитель = %1", Исполнитель), "Ошибка в типе или заполнении аргументов");
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	
	НормаОткрытыхЗаблокированныхЗадач = 1; // значение по умолчанию
	
	//// Найди нормативное значение для количества одновременно открытых заблокированных задач
	//// и если отлично от нуля, используй как норму
	//Парам = Новый Структура();
	//ИмяПараметра = "НормаОткрытыхЗаблокированныхЗадачПоАвтозвонкам";
	//Парам.Вставить(ИмяПараметра);
	//Найдено = РегистрыСведений.УчетнаяПолитика.Получи(Парам);
	//Если Найдено Тогда
	//	НайденнаяНормаОткрытыхЗаблокированныхЗадач = Парам[ИмяПараметра];
	//	
	//	Доступно = ТипЗнч(НайденнаяНормаОткрытыхЗаблокированныхЗадач) = Тип("Число");
	//	Доступно = Доступно И НайденнаяНормаОткрытыхЗаблокированныхЗадач > 0;
	//	Если Доступно Тогда
	//		НормаОткрытыхЗаблокированныхЗадач = НайденнаяНормаОткрытыхЗаблокированныхЗадач;	
	//	КонецЕсли;
	//КонецЕсли;
	
	// Получи количество открытых заблокированных задач на текущую дату и на текущий час
	// Проверка на текущий час защитит от ситуации, когда норма = 1 и возникла ошибочная ситуация,
	// когда есть  в дне есть открытая заблокированная задача, но она не выполнена из-за аварийной ситуации
	//------------------------------------------------------------------------------------------------------
	
	ТекДата = ТекущаяДата();
	
	Запрос = Новый Запрос();
	Запрос.Текст =
	"ВЫБРАТЬ	КОЛИЧЕСТВО(Телефон) КАК Количество
	|ИЗ			РегистрСведений.ЗадачиИнтернетЗаявки
	|ГДЕ
	|	ДатаЗакрытия = ДАТАВРЕМЯ(1, 1, 1, 0, 0, 0)
	|	И Заблокирована = ИСТИНА
	|	И НАЧАЛОПЕРИОДА(ДатаПостановки, ДЕНЬ) = НАЧАЛОПЕРИОДА(&ТекДата, ДЕНЬ)
	|	И НАЧАЛОПЕРИОДА(ДатаПостановки, ЧАС) = НАЧАЛОПЕРИОДА(&ТекДата, ЧАС)
	|	И ВыполнитьАвтозвонок = ИСТИНА";
	Запрос.УстановитьПараметр("ТекДата", ТекДата);
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос, Исполнитель);
	Если Не РезультатЗапроса.Пустой() Тогда
		КоличествоОткрытыхЗаблокированныхЗадач = РезультатЗапроса.Выгрузить()[0][0];
		
		// Если значение больше нормы, не назначай задачу
		//------------------------------------------------------------------------------------
		Если КоличествоОткрытыхЗаблокированныхЗадач >= НормаОткрытыхЗаблокированныхЗадач Тогда
			Возврат ЗначениеПоУмолчанию
		КонецЕсли;
		
	КонецЕсли;
	//</Кошелев_05.09.2017>
	
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ ПЕРВЫЕ 1	Телефон КАК Телефон
	|ИЗ 				РегистрСведений.ЗадачиИнтернетЗаявки
	|ГДЕ
	|	ДатаЗакрытия = ДАТАВРЕМЯ(1, 1, 1, 0, 0, 0)
	|	И Заблокирована = ЛОЖЬ
	|	И ДатаПостановки МЕЖДУ НАЧАЛОПЕРИОДА(&ТекДата, ДЕНЬ) И &ТекДата
	|	И ВыполнитьАвтозвонок = ИСТИНА
	|УПОРЯДОЧИТЬ ПО
	|	ДатаПостановки";	
	Запрос.УстановитьПараметр("ТекДата", ТекДата);	
	РезультатЗапроса =ОбщегоНазначения.ВыполнитьЗапрос(Запрос, Исполнитель);
	Если РезультатЗапроса.Пустой() Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	Выборка = РезультатЗапроса.Выбрать();
	Выборка.Следующий();
	
	НЗ = РегистрыСведений.ЗадачиИнтернетЗаявки.СоздатьМенеджерЗаписи();
	НЗ.Телефон 		= Выборка.Телефон;
	НЗ.ДатаЗакрытия = Дата(1,1,1,0,0,0);
	НЗ.Прочитать();
		
	Если Не НЗ.Выбран() Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	НЗ.Исполнитель		= Исполнитель;
	НЗ.Заблокирована 	= Истина;
	НЗ.ДатаБлокировки	= ТекДата;
	
	Попытка
		НЗ.Записать();
	Исключение
		ЗаписьЖурналаРегистрации("НайдиИЗаблокируйПервуюОткрытуюЗадачу", УровеньЖурналаРегистрации.Ошибка, , СтрШаблон("Телефон = %1, Исполнитель = %2", Выборка.Телефон, Исполнитель), "Ошибка блокировки записи");
		Возврат ЗначениеПоУмолчанию;
	КонецПопытки;
	
	НачатьТранзакцию();

	Блокировка = Новый БлокировкаДанных;
	ЭлементБлокировки = Блокировка.Добавить();
	ЭлементБлокировки.Область="РегистрСведений.ЗадачиИнтернетЗаявки";
	ЭлементБлокировки.Режим = РежимБлокировкиДанных.Исключительный;
	ЭлементБлокировки.УстановитьЗначение("ДатаЗакрытия",'00010101');
	ЭлементБлокировки.УстановитьЗначение("Телефон", Выборка.Телефон);
	//ЭлементБлокировки.УстановитьЗначение("ВыполнитьАвтозвонок", ИСТИНА); 	// не срабатывает: "У пространства блокировок РегистрСведений.ЗадачиИнтернетЗаявки не существует поля с именем ВыполнитьАвтозвонок".
	//ЭлементБлокировки.УстановитьЗначение("ДатаПостановки", Новый Диапазон(НачалоДня(ТекДата), ТекДата));  // регистр сведений нельзя заблокировать по значениям ресурсов и измерений
	Блокировка.Заблокировать(); 

	
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ ПЕРВЫЕ 1
	|	ЗадачиИнтернетЗаявки.Телефон КАК Телефон,
	|	ЗадачиИнтернетЗаявки.Сигнатура КАК Сигнатура,
	|	ЗадачиИнтернетЗаявки.Инициатор КАК Сайт
	|ИЗ
	|	РегистрСведений.ЗадачиИнтернетЗаявки КАК ЗадачиИнтернетЗаявки
	|ГДЕ
	|	ЗадачиИнтернетЗаявки.ДатаЗакрытия = ДАТАВРЕМЯ(1, 1, 1, 0, 0, 0)
	|	И ЗадачиИнтернетЗаявки.Заблокирована = ИСТИНА
	|	И ЗадачиИнтернетЗаявки.ДатаПостановки МЕЖДУ НАЧАЛОПЕРИОДА(&ТекДата, ДЕНЬ) И &ТекДата
	|	И ЗадачиИнтернетЗаявки.ВыполнитьАвтозвонок = ИСТИНА
	|	И ЗадачиИнтернетЗаявки.Телефон = &Телефон
	|
	|УПОРЯДОЧИТЬ ПО
	|	ЗадачиИнтернетЗаявки.ДатаПостановки";
	Запрос.УстановитьПараметр("ТекДата", ТекДата);
	Запрос.УстановитьПараметр("Телефон", Выборка.Телефон);
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос, Исполнитель);
	Если РезультатЗапроса.Пустой() Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	ЗафиксироватьТранзакцию();
	
	Выборка2 = РезультатЗапроса.Выбрать();
	Выборка2.Следующий();
	
	Результат.Вставить("Телефон",	Выборка2.Телефон);
	Результат.Вставить("Сигнатура",	Выборка2.Сигнатура);
	Результат.Вставить("Сайт",		Выборка2.Сайт);
	
	Возврат Результат;
	
КонецФункции

Функция ЗакрепиОткрытуюЗадачуЗаИсполнителем(Телефон) Экспорт
	ЗначениеПоУмолчанию = Ложь;
	Выполнено = УстановиЗначениеИзмерения(Телефон, Телефон, '00010101000000', '00010101000002'); 
	Возврат Выполнено;
КонецФункции

Функция ЗакройОткрытуюЗадачу(Телефон, ДатаЗакрытия, ЗакройЕслиЭтоАвтозвонок = Ложь, Исполнитель="", ЗвонокЗакрытия = "") Экспорт
	//Параметры:
	//	Телефон 	 - Телефон абонента в задаче
	//	ДатаЗакрытия - Дата закрытия задачи 
	//  ЗакройЕслиЭтоАвтозвонок - закрой задачу, если она выполняется автозвонком. Если задача выполняется из консоли
	//		исходящих (перезвон ночных интернет-заявок, не имеющих признак автозвонок), тогда вызываем с ЗакройЕслиАвтозвонок = Ложь, 
	//		чтобы задача автоматически не закрылась. Если задача выполняется автозвонком, тогда в событии HangUp передаем ЗакройЕслиАвтозвонок = Истина
	//		и задача в консоли автоматически закроется 
	//Возвращаемое значение:
	//	Ложь/Истина - если задача не закрылась/закрылась
	
	Доступно = ТипЗнч(Телефон) = Тип("Строка");
	Доступно = Доступно И ЗначениеЗаполнено(Телефон);
	Доступно = Доступно И ТипЗнч(ДатаЗакрытия) = Тип("Дата");
	Доступно = Доступно И ЗначениеЗаполнено(ДатаЗакрытия);
	
	ЗначениеПоУмолчанию = Ложь;

	Данные = "Телефон="+Телефон+"; ДатаЗакрытия="+ДатаЗакрытия+ "; Исполнитель="+Исполнитель;
	Если Не Доступно Тогда
		ЗаписьЖурналаРегистрации("ЗакройОткрытуюЗадачу()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, "Ошибка типа или заполнения аргументов");
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
		
	НЗ = РегистрыСведений.ЗадачиИнтернетЗаявки.СоздатьМенеджерЗаписи();
	НЗ.Телефон = Телефон;
	НЗ.ДатаЗакрытия = '00010101000000';
	НЗ.Прочитать();
	
	Если Не НЗ.Выбран() Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	Если ЗакройЕслиЭтоАвтозвонок = Истина Тогда
		Если НЕ НЗ.ВыполнитьАвтозвонок  Тогда
			Возврат ЗначениеПоУмолчанию;
		КонецЕсли;
	КонецЕсли;
	
	НЗ.ДатаЗакрытия 	= ДатаЗакрытия;
	НЗ.Исполнитель	 	= Исполнитель;
	НЗ.ЗвонокЗакрытия 	= ЗвонокЗакрытия;
	
	Попытка
		НЗ.Записать();
	Исключение
		Комментарий  = ОписаниеОшибки();
		ЗаписьЖурналаРегистрации("ЗакройОткрытуюЗадачу()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, Комментарий);
		Возврат ЗначениеПоУмолчанию;
	КонецПопытки;
	Возврат Истина;
КонецФункции

Функция ЗакройОткрытуюЗадачу2(Телефон, ДатаЗакрытия, ЗакройЕслиЭтоАвтозвонок = Ложь, Исполнитель="") Экспорт
	
	//Параметры:
	//	Телефон 	 - Телефон абонента в задаче
	//	ДатаЗакрытия - Дата закрытия задачи 
	//  ЗакройЕслиЭтоАвтозвонок - закрой задачу, если она выполняется автозвонком. Если задача выполняется из консоли
	//		исходящих (перезвон ночных интернет-заявок, не имеющих признак автозвонок), тогда вызываем с ЗакройЕслиАвтозвонок = Ложь, 
	//		чтобы задача автоматически не закрылась. Если задача выполняется автозвонком, тогда в событии HangUp передаем ЗакройЕслиАвтозвонок = Истина
	//		и задача в консоли автоматически закроется 
	//Возвращаемое значение:
	//	"" - если задача не закрылась
	//	СигнатураИнтернетЗаявки - если задача закрылась
	
	Доступно = ТипЗнч(Телефон) = Тип("Строка");
	Доступно = Доступно И ЗначениеЗаполнено(Телефон);
	Доступно = Доступно И ТипЗнч(ДатаЗакрытия) = Тип("Дата");
	Доступно = Доступно И ЗначениеЗаполнено(ДатаЗакрытия);
	
	ЗначениеПоУмолчанию = "";

	Данные = "Телефон="+Телефон+"; ДатаЗакрытия="+ДатаЗакрытия+ "; Исполнитель="+Исполнитель;
	Если Не Доступно Тогда
		ЗаписьЖурналаРегистрации("ЗакройОткрытуюЗадачу()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, "Ошибка типа или заполнения аргументов");
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
		
	НЗ = РегистрыСведений.ЗадачиИнтернетЗаявки.СоздатьМенеджерЗаписи();
	НЗ.Телефон = Телефон;
	НЗ.ДатаЗакрытия = '00010101000000';
	НЗ.Прочитать();
	
	Если Не НЗ.Выбран() Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	Если ЗакройЕслиЭтоАвтозвонок = Истина Тогда
		Если НЕ НЗ.ВыполнитьАвтозвонок  Тогда
			Возврат ЗначениеПоУмолчанию;
		КонецЕсли;
	КонецЕсли;
	
	НЗ.ДатаЗакрытия = ДатаЗакрытия;
	НЗ.Исполнитель = Исполнитель;
	
	Попытка
		НЗ.Записать();
	Исключение
		Комментарий  = ОписаниеОшибки();
		ЗаписьЖурналаРегистрации("ЗакройОткрытуюЗадачу()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, Комментарий);
		Возврат ЗначениеПоУмолчанию;
	КонецПопытки;
	Возврат "iq_"+НЗ.Сигнатура;
КонецФункции
 
Функция УстановиЗначениеИзмерения(Телефон, НовыйТелефон, ДатаЗакрытия='00010101000000', НоваяДатаЗакрытия='00010101000000') Экспорт
	
	ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ = ЛОЖЬ;
	 
	Доступно = ТипЗнч(Телефон) = Тип("Строка");
	Доступно = Доступно И ЗначениеЗаполнено(Телефон);
	Доступно = Доступно И ТипЗнч(НовыйТелефон) = Тип("Строка");
	Доступно = Доступно И ЗначениеЗаполнено(НовыйТелефон);
	Доступно = Доступно И ТипЗнч(ДатаЗакрытия)=Тип("Дата");
	Доступно = Доступно И ТипЗнч(НоваяДатаЗакрытия)=Тип("Дата");

	НЗ = РегистрыСведений.ЗадачиИнтернетЗаявки.СоздатьМенеджерЗаписи();
	НЗ.Телефон=Телефон;
	НЗ.ДатаЗакрытия = ДатаЗакрытия;
	НЗ.Прочитать();
	
	Если Не НЗ.Выбран() Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ
	КонецЕсли;
 
	НЗ.Телефон = НовыйТелефон;
	НЗ.ДатаЗакрытия = НоваяДатаЗакрытия;
	
	Для Каждого Рекв Из Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки.Реквизиты Цикл
		НЗ[Рекв.Имя] = НЗ[Рекв.Имя];
	КонецЦикла;
	
	//НЗ.Комментарий = НЗ.Комментарий + Символы.ПС+" "+ТекущаяДата()+" изменен телефон с "+Телефон +" на "+НовыйТелефон+" пользователем "+ПараметрыСеанса.ТекущийПользователь;
	
	Данные = "Телефон="+Телефон+"; НовыйТелефон="+НовыйТелефон+"; ДатаЗакрытия="+ДатаЗакрытия+"; НоваяДатаЗакрытия="+НоваяДатаЗакрытия; 
	Попытка
		НЗ.Записать();
	Исключение
		ЗаписьЖурналаРегистрации("УстановиЗначениеИзмерения()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, "Ошибка записи");
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
	КонецПопытки;
	
	Возврат ИСТИНА;

КонецФункции

Функция УстановиЗначениеРеквизита(Телефон, ИмяРеквизита, ЗначениеРеквизита) Экспорт
	
	ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ = Ложь;
	
	
	Доступно = ТипЗнч(Телефон) = Тип("Строка");
	Доступно = Доступно И ЗначениеЗаполнено(Телефон);
	Доступно = Доступно И ТипЗнч(ИмяРеквизита)=Тип("Строка");
	Доступно = Доступно И ТипЗнч(ЗначениеРеквизита)<> Тип("Неопределено");
	Доступно = Доступно И ЗначениеЗаполнено(ЗначениеРеквизита);
	
	Если Не Доступно Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ
	КонецЕсли;
	
	НЗ 				= 	РегистрыСведений.ЗадачиИнтернетЗаявки.СоздатьМенеджерЗаписи();
	НЗ.Телефон		=	Телефон;
	НЗ.ДатаЗакрытия	=	'00010101';
	НЗ.Прочитать();
	
	Если Не НЗ.Выбран() Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ
	КонецЕсли;
	
	ИзмененоЗначениеРеквизита = Ложь;
	НЗ.Телефон 		=	Телефон;
	НЗ.ДатаЗакрытия =	'00010101';
	Для Каждого Рекв Из Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки.Реквизиты Цикл
		НЗ[Рекв.Имя] = НЗ[Рекв.Имя];
		Если Рекв.Имя <> ИмяРеквизита Тогда
			Продолжить
		КонецЕсли;
		Если Не Рекв.Тип.СодержитТип(ТипЗнч(ЗначениеРеквизита)) Тогда
			Продолжить
		КонецЕсли;
		
		НЗ.Комментарий = НЗ.Комментарий + Символы.ПС+" "+ТекущаяДата()+" изменен "  +ИмяРеквизита+ " с """+НЗ[Рекв.Имя]+""" на """+ЗначениеРеквизита+""" пользователем "+ПараметрыСеанса.ТекущийПользователь;
		НЗ[Рекв.Имя] = ЗначениеРеквизита;
		ИзмененоЗначениеРеквизита = Истина;
		Прервать;
	КонецЦикла;

	
	Если Не ИзмененоЗначениеРеквизита Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
	КонецЕсли;

	Попытка
			НЗ.Записать();
			Возврат Истина;
	Исключение
			ЗаписьЖурналаРегистрации("УстановиЗначениеРеквизита()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, , ОписаниеОшибки());
			Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
	КонецПопытки;
		
КонецФункции

Функция ИзмениРеквизит(Телефон, ДатаЗакрытия, ИмяРеквизита, ЗначениеРеквизита)		
	ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ = Ложь;
	 
	Доступно = ТипЗнч(Телефон) = Тип("Строка");
	Доступно = Доступно И ТипЗнч(ДатаЗакрытия) = Тип("Дата");
	Доступно = Доступно И ТипЗнч(ИмяРеквизита) = Тип("Строка");
	
	Доступно = Доступно И ЗначениеЗаполнено(Телефон);
	Доступно = Доступно И ЗначениеЗаполнено(ИмяРеквизита);
		
	Если Не Доступно Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
	КонецЕсли;
	
	НЗ = РегистрыСведений.ЗадачиИнтернетЗаявки.СоздатьМенеджерЗаписи();
	НЗ.Телефон		= Телефон;
	НЗ.ДатаЗакрытия 	= ДатаЗакрытия;
	НЗ.Прочитать();
	
	Данные = "Телефон = "+ Телефон +";ДатаЗакрытия = "+ДатаЗакрытия;
	Если Не НЗ.Выбран() Тогда
		ЗаписьЖурналаРегистрации("ИзмениРеквизит()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, "Запись не найдена");
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ
	КонецЕсли;
 
	НЗ.Телефон		= Телефон;
	НЗ.ДатаЗакрытия = ДатаЗакрытия;
	
	Для Каждого Рекв Из Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки.Реквизиты Цикл
		Если Рекв.Имя = ИмяРеквизита Тогда
			 СтароеЗначениеРеквизита = НЗ[Рекв.Имя];
			 НЗ[Рекв.Имя] = ЗначениеРеквизита;
		Иначе
			НЗ[Рекв.Имя] = НЗ[Рекв.Имя];
		КонецЕсли;
	КонецЦикла;
	
	//НЗ.Комментарий = НЗ.Комментарий + Символы.ПС+" "+ТекущаяДата()+" изменен "  +ИмяРеквизита+ " с "+СтароеЗначение+" на "+НовоеЗначение+" пользователем "+ПараметрыСеанса.ТекущийПользователь;
	
	Попытка
		НЗ.Записать();
	Исключение
		ЗаписьЖурналаРегистрации("ИзмениРеквизит()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, "Ошибка записи");
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
	КонецПопытки;
	
	Возврат Истина;

КонецФункции

Функция ИзмениРеквизиты(Телефон, ДатаЗакрытия, ИменаИЗначенияРеквизитов) Экспорт
	
	ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ = Ложь;
	 
	Доступно = ТипЗнч(Телефон) = Тип("Строка");
	Доступно = Доступно И ТипЗнч(ДатаЗакрытия) = Тип("Дата");
	Доступно = Доступно И ТипЗнч(ИменаИЗначенияРеквизитов) = Тип("Структура");
	Доступно = Доступно И ЗначениеЗаполнено(Телефон);
	
		
	Если Не Доступно Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
	КонецЕсли;
	
	НЗ = РегистрыСведений.ЗадачиИнтернетЗаявки.СоздатьМенеджерЗаписи();
	НЗ.Телефон			= Телефон;
	НЗ.ДатаЗакрытия 	= ДатаЗакрытия;
	НЗ.Прочитать();
	
	Данные = "Телефон = "+ Телефон +";ДатаЗакрытия = "+ДатаЗакрытия;
	Если Не НЗ.Выбран() Тогда
		ЗаписьЖурналаРегистрации("ИзмениРеквизиты()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, "Запись не найдена");
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ
	КонецЕсли;
 	
	ТекДата 		= ТекущаяДата();
	Для Каждого Рекв Из Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки.Реквизиты Цикл
		
		ЗначениеРеквизита = Неопределено; //инициализация
		
		//Если имя реквизита найдено в переданных функцию именах реквизитов, тогда измени значение этого реквизита
		//--------------------------------------------------------------------------------------------------------
		Если ИменаИЗначенияРеквизитов.Свойство(Рекв.Имя, ЗначениеРеквизита)= Истина Тогда
			
			Если ЗначениеРеквизита = Неопределено Тогда
				Продолжить;
			КонецЕсли;
			
			 СтароеЗначениеРеквизита = НЗ[Рекв.Имя];
			 НЗ[Рекв.Имя] = ЗначениеРеквизита;
			 
			 НЗ.Комментарий = НЗ.Комментарий + "; "+ТекДата+" изменен "  +Рекв.Имя+ " с "+СтароеЗначениеРеквизита+" на "+ЗначениеРеквизита;

		Иначе
			НЗ[Рекв.Имя] = НЗ[Рекв.Имя];
		КонецЕсли;
		
	КонецЦикла;
	
	
	Попытка
		НЗ.Записать();
	Исключение
		ЗаписьЖурналаРегистрации("ИзмениРеквизит()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, "Ошибка записи");
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
	КонецПопытки;
	
	Возврат Истина;

КонецФункции

Функция НайдиИнициатораПоТелефонуОтрытойЗадачи(Телефон) Экспорт
	
	ЗначениеПоУмолчанию = "неопределено";
	
	Доступно = ТипЗнч(Телефон) = Тип ("Строка");
	Доступно = Доступно И ЗначениеЗаполнено(Телефон);
	
	Если Не Доступно Тогда
		Данные = "Телефон="+Телефон;
		ЗаписьЖурналаРегистрации("НайдиИнициатораПоТелефону", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, "Ошибка типа или заполнения аргумента");
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ ПЕРВЫЕ 1
	|	ЗадачиИнтернетЗаявки.Инициатор
	|ИЗ
	|	РегистрСведений.ЗадачиИнтернетЗаявки КАК ЗадачиИнтернетЗаявки
	|ГДЕ
	|	ЗадачиИнтернетЗаявки.Телефон = &Телефон
	|	И ЗадачиИнтернетЗаявки.Заблокирована = ИСТИНА";
	Запрос.УстановитьПараметр("Телефон", Телефон);
	РезультатЗапроса = Запрос.Выполнить();
	Если РезультатЗапроса = Неопределено Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	Рез = РезультатЗапроса.Выгрузить()[0][0];
	Возврат Рез;
	
КонецФункции

Функция УстановиЗначениеРеквизитаИЗакройЗадачу(Телефон, ДатаЗакрытия, ИмяРеквизита, ЗначениеРеквизита, ТекущийПользователь="") Экспорт
	
	Данные = "Телефон="+Телефон+"; ДатаЗакрытия="+ДатаЗакрытия+"; ИмяРеквизита="+ИмяРеквизита+"; ЗначениеРеквизита="+ЗначениеРеквизита+"; ТекущийПользователь="+ТекущийПользователь;
	
	ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ = ЛОЖЬ;
	
	Доступно = ТипЗнч(Телефон) = Тип("Строка");
	Доступно = Доступно И ЗначениеЗаполнено(Телефон);
	Доступно = Доступно И ТипЗнч(ДатаЗакрытия)=Тип("Дата");
	Доступно = Доступно И ЗначениеЗаполнено(ДатаЗакрытия);
	Доступно = Доступно И ТипЗнч(ИмяРеквизита)=Тип("Строка");
	
	Если Не Доступно Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ
	КонецЕсли;
	
	НЗ = РегистрыСведений.ЗадачиИнтернетЗаявки.СоздатьМенеджерЗаписи();
	НЗ.Телефон=Телефон;
	НЗ.ДатаЗакрытия=Дата("00010101");
	НЗ.Прочитать();
	
	Если Не НЗ.Выбран() Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ
	КонецЕсли;
	
	ИзмененоЗначениеРеквизита = Ложь;
	НЗ.Телефон = НЗ.Телефон;
	НЗ.ДатаЗакрытия = НЗ.ДатаЗакрытия;
	Для Каждого Рекв Из Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки.Реквизиты Цикл
		НЗ[Рекв.Имя] = НЗ[Рекв.Имя];
		Если Рекв.Имя <> ИмяРеквизита Тогда
			Продолжить
		КонецЕсли;
		Если Не Рекв.Тип.СодержитТип(ТипЗнч(ЗначениеРеквизита)) Тогда
			Продолжить
		КонецЕсли;
		 НЗ[Рекв.Имя] = ЗначениеРеквизита;
		 ИзмененоЗначениеРеквизита = ИСТИНА;
		 Прервать;
	КонецЦикла;
	
	Если ИзмененоЗначениеРеквизита Тогда
		НЗ.ДатаЗакрытия = ДатаЗакрытия;
		Если ЗначениеЗаполнено(ТекущийПользователь) Тогда
			НЗ.Исполнитель = ТекущийПользователь;
		КонецЕсли;
		Попытка
			НЗ.Записать();
		Исключение
			Комментарий = ОписаниеОшибки();
			ЗаписьЖурналаРегистрации("УстановиЗначениеРеквизитаИЗакройЗадачу", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ЗадачиИнтернетЗаявки, Данные, Комментарий);
			Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
		КонецПопытки;
		
		Возврат ИСТИНА;
		
	КонецЕсли;
	
	
КонецФункции
