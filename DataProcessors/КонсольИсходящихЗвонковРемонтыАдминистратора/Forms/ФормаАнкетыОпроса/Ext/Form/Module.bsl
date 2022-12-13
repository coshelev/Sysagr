﻿&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	ЭтаФорма.ИмяАктивногоДинамичСписка = "ЗадачиСписокЛояльностьРемонта";
	
	Если Не ЗначениеЗаполнено(ЭтаФорма.Параметры.Телефон) Тогда
		Сообщить("Не передан параметр: телефон");
	КонецЕсли;
	
	Телефон = ЭтаФорма.Параметры.Телефон;
	ЗаполниТаблицуВопросовТребующихВводОтветов(ЭтаФорма.ИмяАктивногоДинамичСписка,Телефон);
КонецПроцедуры

&НаСервере
Процедура ЗаполниТаблицуВопросовТребующихВводОтветов(ИмяАктивногоДинамическогоСписка,Телефон);
	//Используется для звонков и почты
	
	Если Не ЗначениеЗаполнено(ИмяАктивногоДинамическогоСписка) Тогда
		Возврат
	КонецЕсли;
	
	Если Не ЗначениеЗаполнено(Телефон) Тогда
		Возврат
	КонецЕсли;
	
	Если ЭтаФорма.ТаблицаВведенныхОтветов.Количество()>0 Тогда
		ЭтаФорма.ТаблицаВведенныхОтветов.Очистить();
	КонецЕсли;
	
	Если ЭтаФорма.ТаблицаВопросОтвет.Количество()>0 Тогда
		ЭтаФорма.ТаблицаВопросОтвет.Очистить();
	КонецЕсли;
	
	Запрос = Новый Запрос();
	Запрос.Текст =
	
	"ВЫБРАТЬ
	|	Анкеты.Ссылка КАК Вопрос,
	|	Анкеты.Наименование КАК ВопросСтрокой,
	|	Анкеты.Порядок КАК Порядок,
	|	ЕСТЬNULL(ИдентификаторыВопросов.Ссылка, ЗНАЧЕНИЕ(Справочник.ИдентификаторыСтрок.ПустаяСсылка)) КАК ИдВопроса
	|ПОМЕСТИТЬ ВТ00_ТекущиеВопросыАнкеты
	|ИЗ
	|	Справочник.Анкеты КАК Анкеты
	|		ЛЕВОЕ СОЕДИНЕНИЕ Справочник.ИдентификаторыСтрок КАК ИдентификаторыВопросов
	|		ПО (ИдентификаторыВопросов.МодифицированнаяСтрока = Анкеты.МодифицированнаяСтрока)
	|ГДЕ
	|	Анкеты.ПометкаУдаления = ЛОЖЬ
	|	И Анкеты.ЭтоГруппа = ЛОЖЬ
	|	И Анкеты.Родитель.Наименование ПОДОБНО &НаименованиеГруппы
	|	И Анкеты.НеПоказыватьПредыдущийОтвет = ЛОЖЬ
	|
	|ИНДЕКСИРОВАТЬ ПО
	|	Вопрос,
	|	ИдВопроса
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ РАЗЛИЧНЫЕ
	|	ВариантыОтветов.Ссылка КАК Вопрос
	|ПОМЕСТИТЬ ВТ01_ВопросыСВыборомОтвета
	|ИЗ
	|	Справочник.Анкеты.ВариантыОтветов КАК ВариантыОтветов
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ ВТ00_ТекущиеВопросыАнкеты КАК Анкеты
	|		ПО ВариантыОтветов.Ссылка = Анкеты.Вопрос
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ00.Вопрос КАК Вопрос,
	|	ВТ00.ВопросСтрокой КАК ВопросСтрокой,
	|	ВТ00.ИдВопроса КАК ИдВопроса,
	|	ВТ00.Порядок КАК Порядок,
	|	ВЫБОР
	|		КОГДА ВТ00.Вопрос = ЕСТЬNULL(ВТ01.Вопрос, ЗНАЧЕНИЕ(Справочник.Анкеты.ПустаяСсылка))
	|			ТОГДА ИСТИНА
	|		ИНАЧЕ ЛОЖЬ
	|	КОНЕЦ КАК ВопросТребуетВыбораОтвета
	|ИЗ
	|	ВТ00_ТекущиеВопросыАнкеты КАК ВТ00
	|		ЛЕВОЕ СОЕДИНЕНИЕ ВТ01_ВопросыСВыборомОтвета КАК ВТ01
	|		ПО (ВТ01.Вопрос = ВТ00.Вопрос)
	|
	|УПОРЯДОЧИТЬ ПО
	|	ВТ00.Порядок";
	
	Запрос.УстановитьПараметр("ТекущаяДата", ТекущаяДата());	
	Запрос.УстановитьПараметр("Телефон", Телефон);
	
	Если ИмяАктивногоДинамическогоСписка = "ЗадачиСписокЛояльностьРемонта" Тогда
		 Запрос.УстановитьПараметр("НаименованиеГруппы", "%ЛОЯЛЬНОСТЬ_РЕМОНТА%");
	КонецЕсли;

	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	Если РезультатЗапроса.Пустой() Тогда
		Возврат
	КонецЕсли;
	
	Выборка = РезультатЗапроса.Выбрать();
	Пока Выборка.Следующий() Цикл
			
		//Заполни таблицу ТаблицаВведенныхОтветов
		//----------------------------------------------------------------------------
		НоваяСтрока = ЭтаФорма.ТаблицаВведенныхОтветов.Добавить();
		НоваяСтрока.ВопросАнкеты 				= Выборка.Вопрос;
		НоваяСтрока.ВопросСтрокой 				= Выборка.ВопросСтрокой;
		НоваяСтрока.ВопросТребуетВыбораОтвета	= Выборка.ВопросТребуетВыбораОтвета;
				
		//Заполни кэш вопросов-ответов
		//----------------------------------------------------------------------------
		НовСтрока = ЭтаФорма.ТаблицаВопросОтвет.Добавить();
		НовСтрока.Вопрос 							= 	Выборка.Вопрос;
		НовСтрока.Ответ								=	"";
		НовСтрока.ПорядковыйНомерВопроса 			= 	Выборка.Порядок;
	КонецЦикла;

КонецПроцедуры

#Область ТаблицаВведенныхОтветов

&НаКлиенте
Процедура ТаблицаВведенныхОтветовОтветСтрокойНачалоВыбора(Элемент, ДанныеВыбора, СтандартнаяОбработка)
	
	ВопросАнкеты 	= Элемент.Родитель.Родитель.ТекущиеДанные.ВопросАнкеты;
	СписокОтветов 	= ТаблицаВведенныхОтветов_ПолучиСписокОтветов_НаСервере(ВопросАнкеты);
	ВопросТребуетОбновитьОтвет = Элемент.Родитель.Родитель.ТекущиеДанные.ВопросТребуетОбновитьОтвет;
	Если СписокОтветов.Количество()>0 Тогда
		ДопПарамОбработчикаОповещения = Новый Структура("ВопросАнкеты", ВопросАнкеты); 
		Оп = Новый ОписаниеОповещения("ОбработкаОповещения_ТаблицаВведенныхОтветовОтветНачалоВыбора", ЭтотОбъект, ДопПарамОбработчикаОповещения);
		ПоказатьВыборИзСписка(Оп, СписокОтветов, Элемент);
	КонецЕсли;

КонецПроцедуры

&НаКлиенте
Процедура ОбработкаОповещения_ТаблицаВведенныхОтветовОтветНачалоВыбора(ВыбЗначОтвет, ДопПараметры) Экспорт
	
	Если ВыбЗначОтвет = Неопределено Тогда
		Возврат;
	КонецЕсли;
		
	НайденныеСтроки = ЭтаФорма.ТаблицаВведенныхОтветов.НайтиСтроки(ДопПараметры); // должны найти одну строку
	Если НайденныеСтроки.Количество()<>1 Тогда
		Возврат
	КонецЕсли;

	НайденныеСтроки[0].ОтветСтрокой = ВыбЗначОтвет.Значение;
	ДобавитьЗаписьВТаблицуВопросОтвет(ДопПараметры.ВопросАнкеты, ВыбЗначОтвет.Значение);
	НайденныеСтроки[0].ФорматТекстаОтвета = 2;
	
КонецПроцедуры

&НаСервере
Функция ТаблицаВведенныхОтветов_ПолучиСписокОтветов_НаСервере(ВопросАнкеты)
	сзОтветы = Новый СписокЗначений();

	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	АнкетыВариантыОтветов.Ответ КАК Ответ
	|ИЗ
	|	Справочник.Анкеты.ВариантыОтветов КАК АнкетыВариантыОтветов
	|ГДЕ
	|	АнкетыВариантыОтветов.Ссылка = &Ссылка";
	Запрос.УстановитьПараметр("Ссылка", ВопросАнкеты);
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	Если РезультатЗапроса.Пустой() Тогда
		Возврат сзОтветы
	КонецЕсли;
	Выборка = РезультатЗапроса.Выбрать();
	Пока Выборка.Следующий() Цикл
		сзОтветы.Добавить(Выборка.Ответ);
	КонецЦикла;
	Возврат сзОтветы;
		
КонецФункции

&НаКлиенте
Процедура ТаблицаВведенныхОтветовОтветСтрокойОкончаниеВводаТекста(Элемент, Текст, ДанныеВыбора, ПараметрыПолученияДанных, СтандартнаяОбработка)
	
	ТекДанные = ЭтаФорма.Элементы.ТаблицаВведенныхОтветов.ТекущиеДанные;
	
	//Выход, если вопрос требует выбора, а не ввода ответа
	//----------------------------------------------------
	Если ТекДанные.ВопросТребуетВыбораОтвета Тогда 
		СтандартнаяОбработка=Ложь;
		Возврат
	КонецЕсли;
	ТекДанные.ФорматТекстаОтвета = 2;
	ДобавитьЗаписьВТаблицуВопросОтвет(ТекДанные.ВопросАнкеты, Текст);
	Элемент.СписокВыбора.Очистить();
	
КонецПроцедуры

&НаКлиенте
Процедура ТаблицаВведенныхОтветовОтветКомментарийСтрокойОкончаниеВводаТекста(Элемент, Текст, ДанныеВыбора, ПараметрыПолученияДанных, СтандартнаяОбработка)
	
	ТекДанные = ЭтаФорма.Элементы.ТаблицаВведенныхОтветов.ТекущиеДанные;	
	ТекДанные.ФорматТекстаОтвета = 2;
	ДобавитьЗаписьВТаблицуВопросОтвет(ТекДанные.ВопросАнкеты, ,Текст);	
КонецПроцедуры

&НаКлиенте
Процедура ТаблицаВведенныхОтветовОтветСтрокойОчистка(Элемент, СтандартнаяОбработка)
	//Замени в кэше вопросов-ответов ответ на ""
	
	ТекДанные 		= Элементы.ТаблицаВведенныхОтветов.ТекущиеДанные;
	ВопросАнкеты 	= ТекДанные.ВопросАнкеты;
	ДобавитьЗаписьВТаблицуВопросОтвет(ВопросАнкеты, "");
КонецПроцедуры

#КонецОбласти

&НаСервере
Процедура ДобавитьЗаписьВТаблицуВопросОтвет(ВопросАнкеты, Ответ="", ОтветКомментарий = "")
	
	Отбор 			= Новый Структура("Вопрос", ВопросАнкеты);
	НайденныеСтроки = ЭтаФорма.ТаблицаВопросОтвет.НайтиСтроки(Отбор);
	СтрокаТЧ 		= ?(НайденныеСтроки.Количество()>0, НайденныеСтроки[0], ТаблицаВопросОтвет.Добавить());
	СтрокаТЧ.Вопрос = ВопросАнкеты;
	
	Если ЗначениеЗаполнено(Ответ) Тогда //значит позльзователь ввел/выбрал значение для поля Ответ
		СтрокаТЧ.Ответ = Ответ;
	КонецЕсли;
	
	Если ЗначениеЗаполнено(ОтветКомментарий) Тогда //значит позльзователь ввел/выбрал значение для поля ОтветКомментарий
		СтрокаТЧ.ОтветКомментарий = ОтветКомментарий;
	КонецЕсли;
	
КонецПроцедуры

&НаСервереБезКонтекста
Функция ЭтоНегативнаяАнкета(СигнатураПродажи) Экспорт
	Возврат Анкета.ЭтоНегативнаяАнкета(СигнатураПродажи);
КонецФункции

&НаКлиенте
Процедура ЗаписатьАнкету(Команда)
	
	ТекДата = ТекущаяДата();
	ДатаАнкеты = ТекДата;;
	
	Тел = ЭтаФорма.Параметры.Телефон;
	
	Доступно = ЗначениеЗаполнено(Тел);
	Доступно = Доступно И  ТаблицаВопросОтвет.Количество()>0;
	
	Если Не Доступно Тогда
		ПоказатьПредупреждение(, "Запись анкеты невозможна. Не указан телефон абонента или не заполнена анкета", 3);
		Возврат
	КонецЕсли;
	
	Для Каждого Зап Из ТаблицаВопросОтвет Цикл
		Если Не ЗначениеЗаполнено(Зап.Ответ) Тогда
			ПоказатьПредупреждение(, "Запись анкеты невозможна. Анкета заполнена не полностью", 3);
			Возврат;
		КонецЕсли;
	КонецЦикла;
		
	// Запиши анкету
	//--------------
	СигнатураПродажи = ЭтаФорма.Параметры.СигнатураПродажи;
	
	Доступно = ЗаписатьВыбранныйОтвет_НаСервере(ДатаАнкеты, Тел, СигнатураПродажи);
	Если Не Доступно Тогда	
		ПоказатьПредупреждение(, "Ошибка записи анкеты", 3);
	КонецЕсли;
	
	//Закрой задачу
	//-------------
	Успех = ЗакройЗадачуЛояльностиНаСервере(СигнатураПродажи, ДатаАнкеты);
	Если Не Успех Тогда
		ПоказатьПредупреждение(, "Ошибка закрытия задачи", 3);
	КонецЕсли;                                                                                                         
	
	//16.10.2017,+, Закрой спакетированные задачи
	//-------------------------------------------
	ЗакройСпакетированныеЗадачи(СигнатураПродажи, ДатаАнкеты);
	
	Оповестить("Анкета сохранена, задача закрыта", СигнатураПродажи); 
	
	ЭтаФорма.НегативнаяАнкета = ЭтоНегативнаяАнкета(СигнатураПродажи);
	Если ЭтаФорма.НегативнаяАнкета Тогда
				
		//Определи реквизит адресации подразделение-исполнитель и доп.реквизит адресации
		//---------------------------------------------------------------------------------
		ПодрИсполнитель 	 = ПредопределенноеЗначение("Справочник.Предприятие.ПустаяСсылка");
		ДопРеквизитАдресации = "";
		
		Отб = Новый Структура();
		Отб.Вставить("ТочкаПродажи", ЭтаФорма.Параметры.ТочкаПродажи);
		Найденные = ЭтаФорма.ВладелецФормы.Объект.ТочкиПродажиВПодразделения.НайтиСтроки(Отб);
		Если Найденные.Количество() = 1 Тогда
			ПодрИсполнитель 	 = Найденные[0].Подразделение;
			ДопРеквизитАдресации = Найденные[0].ДопРеквизитАдресации; 
		Иначе
			Сообщить("Сообщите администратору. Не найдено подразделение для точки "+ЭтаФорма.Параметры.ТочкаПродажи);
		КонецЕсли;
		
		//Определи реквизит адресации подразделение-контролер
		//----------------------------------------------------
		ПодрКонтролер = ПодразделениеКонтролер();// "Департамент работы с клиентами/Клиентская служба"

		//Если пытаемся запустить бизнес-процесс по ранее закрытой задаче
		//----------------------------------------------------------------
		   
		СтартуйБП(ЭтаФорма.Параметры.СигнатураПродажи, ТекДата, ТекДата, ЭтаФорма.Параметры.ТочкаПродажи, ЭтаФорма.Параметры.Телефон, ПодрИсполнитель, ПодрКонтролер, ДопРеквизитАдресации)
	КонецЕсли;

	ЭтаФорма.Закрыть();
КонецПроцедуры

&НаСервереБезКонтекста
Функция ПодразделениеКонтролер()
	Возврат Справочники.Предприятие.НайтиПоКоду("000002320");
КонецФункции

&НаСервере
Функция СтартуйБП(СигнатураПродажи, Дата, ДатаСтарта, ТочкаПродажи, Телефон, ПодразделениеИсполнитель, ПодразделениеКонтролер = Неопределено, ДопРеквизитАдресации = "")
	
	ТекДата = ТекущаяДата();
	
	//Запусти процесс формирования задач обработки негативных анкет
	//-------------------------------------------------------------
	БП 					= БизнесПроцессы.ОбратнаяСвязьЛояльности.СоздатьБизнесПроцесс();
	БП.Дата 			= Дата;
	БП.ДатаСтарта		= Дата;
	БП.Точка			= ТочкаПродажи;
	БП.СигнатураПродажи	= СигнатураПродажи;
	БП.Телефон			= Телефон;
	Если ЗначениеЗаполнено(ПодразделениеИсполнитель) Тогда
		БП.ПодразделениеИсполнитель = ПодразделениеИсполнитель;
	Иначе
		Подр = Справочники.Предприятие.НайтиПоКоду("000001345"); //Кошелев
		БП.ПодразделениеИсполнитель = Подр;
	КонецЕсли;
	
	БП.ДопРеквизитАдресации = ДопРеквизитАдресации;
	
	// Подразделение-контролер
	//---------------------------------------------------------------------
	ПодрК = ПодразделениеКонтролер;
	Если ПодрК = Неопределено Тогда
		ПодрК = Справочники.Предприятие.НайтиПоКоду("000002320");// "Департамент работы с клиентами/Клиентская служба"			
	КонецЕсли;
	БП.ПодразделениеКонтролер = ПодрК;

	БП.Записать();
	БП.Старт();	
	
КонецФункции

&НаСервере 
Функция ЗакройСпакетированныеЗадачи(СигнатураМастерПродажи, ДатаАнкеты)
	ЗначениеПоУмолчанию = Ложь;
	
	НачатьТранзакцию();
	
	
	Для Каждого ПодобнаяЗадача Из ЭтаФорма.Параметры.ПакетЗаказНарядов Цикл
		
		//Если ПодобнаяЗадача.Спакетировать Тогда
		
			Успех = ЗапишиПакетЗадач(СигнатураМастерПродажи, ПодобнаяЗадача.Значение);
			Если Не Успех Тогда
				ОтменитьТранзакцию();	
				Возврат ЗначениеПоУмолчанию;
			КонецЕсли;
			
			Успех = ЗакройЗадачуЛояльностиНаСервере(ПодобнаяЗадача.Значение, ДатаАнкеты);
			Если Не Успех Тогда
				ОтменитьТранзакцию();	
				Возврат ЗначениеПоУмолчанию;
			КонецЕсли;
			
		//КонецЕсли;
	КонецЦикла;
	
	ЭтаФорма.Объект.Ремонты_ПодобныеЗадачи.Очистить();
	ЗафиксироватьТранзакцию();
	Возврат Истина;
КонецФункции

&НаСервере
Функция ЗапишиПакетЗадач(СигнатураМастерЗадачи, СигнатураЗадачи)
	Возврат РегистрыСведений.ЗадачиЛояльностиПакеты.Добавить(СигнатураМастерЗадачи, СигнатураЗадачи);
КонецФункции

&НаСервере
Функция ЗакройЗадачуЛояльностиНаСервере(СигнатураПродажи, ДатаАнкеты)
	
	ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ = Ложь;
	
	Доступно = ТипЗнч(СигнатураПродажи) = Тип("Строка");
	Доступно = Доступно И ЗначениеЗаполнено(СигнатураПродажи);
	Доступно = Доступно И ТипЗнч(ДатаАнкеты) = Тип("Дата");
	Доступно = Доступно И ЗначениеЗаполнено(ДатаАнкеты);
	
	Если Не Доступно Тогда 
		Данные = "СигнатураПродажи="+СигнатураПродажи+" ;ДатаАнкеты="+ДатаАнкеты;
		ЗаписьЖурналаРегистрации("ЗакройЗадачуЛояльностиНаСервере()", УровеньЖурналаРегистрации.Ошибка, Метаданные.Обработки.КонсольИсходящихЗвонков, Данные, "Ошибка в типах или заполнении аргументов");
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
	КонецЕсли;
	
	ЗначРекв = ЭтаФорма.Параметры.ЗвонокЗакрытия;

	Доступно = ЗначениеЗаполнено(ЗначРекв);	
	Если Не Доступно Тогда
		Данные = ЗначРекв;
		ЗаписьЖурналаРегистрации("ЗакройЗадачуЛояльностиНаСервере()", УровеньЖурналаРегистрации.Ошибка, Метаданные.Обработки.КонсольИсходящихЗвонков, Данные, "Не заполнено значение реквизита");
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ
	КонецЕсли;
	
	Успех = РегистрыСведений.ЗадачиЗвонокЛояльности.УстановиЗначениеРеквизитаИЗакройЗадачу(СигнатураПродажи, ДатаАнкеты, "ЗвонокЗакрытия", ЗначРекв, ПараметрыСеанса.ТекущийПользователь);
	
	Если Не Успех Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ
	КонецЕсли;
	
	Возврат Истина;
КонецФункции

&НаСервере
Функция ЗаписатьВыбранныйОтвет_НаСервере(ДатаАнкеты, ТелАбонента, СигнатураЗадачи = "")
	//Эапись в регистр сведений АнкетыРасширенные
	
	ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ = Ложь;
	
	Доступно = ТипЗнч(ДатаАнкеты) = Тип("Дата");
	Доступно = Доступно И ЗначениеЗаполнено(ДатаАнкеты);
	Доступно = Доступно И ТипЗнч(ТелАбонента) = Тип("Строка") ;
	Доступно = Доступно И ЗначениеЗаполнено(ТелАбонента);
	
	Если Не Доступно Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
	КонецЕсли;
	
	
	
	
	ПустойИд = Справочники.ИдентификаторыСтрок.ПустаяСсылка();
	
	НЗ = РегистрыСведений.АнкетыРасширенные.СоздатьНаборЗаписей();
	НЗ.Отбор.Период.Установить(ДатаАнкеты);
	НЗ.Отбор.Телефон.Установить(ТелАбонента);
	НЗ.Прочитать();
	
	//<Запись ответов на вопросы  и самих вопросов анкеты. Вопросы маршрутизации записываются в момент выбора строки списка>
	Для Каждого Эл Из ЭтаФорма.ТаблицаВопросОтвет Цикл
		
		//Не записываем, если ответ не заполнен
		//-----------------------------------------------------
		Если Не ЗначениеЗаполнено(Эл.Ответ) Тогда
			Продолжить;
		КонецЕсли;
		
		ИдСтрокиВопроса = Справочники.ИдентификаторыСтрок.УстановиИдентификаторСтроки(Строка(Эл.Вопрос), "вопрос", Строка(Эл.Вопрос));
		
		Если ИдСтрокиВопроса = ПустойИд Тогда
			Продолжить
		КонецЕсли;
		
		ИдСтрокиОтвета  = Справочники.ИдентификаторыСтрок.УстановиИдентификаторСтроки(Эл.Ответ, "ответ_комментарий", Эл.Ответ);
		
		//Если ответ не выбран или не введен,  тогда записываем пустую ссылку 
		//-------------------------------------------------------------------
		//Если ИдСтрокиОтвета = ПустойИд Тогда
		//	Продолжить
		//КонецЕсли;
		
		ИдСтрокиОтветКомментарий  = Справочники.ИдентификаторыСтрок.УстановиИдентификаторСтроки(Эл.ОтветКомментарий, "ответ", Эл.ОтветКомментарий);

		НоваяЗапись = НЗ.Добавить();
		НоваяЗапись.Период								=	ДатаАнкеты;
		НоваяЗапись.Телефон 							=	ТелАбонента;
		НоваяЗапись.Вопрос								=	ИдСтрокиВопроса;
		НоваяЗапись.СигнатураЗадачQ						=	СигнатураЗадачи;
		НоваяЗапись.Ответ								=	ИдСтрокиОтвета;
		НоваяЗапись.ОтветКомментарий					=   ИдСтрокиОтветКомментарий;
		НоваяЗапись.ПорядковыйНомерВопроса 				=	Эл.ПорядковыйНомерВопроса;
		НоваяЗапись.СигнатураЗадачи						=	СигнатураЗадачи; 
	КонецЦикла;
	//</Запись ответов на вопросы и самих вопросов>
	
	Если НЗ.Количество()>0 Тогда
		Попытка
			НЗ.Записать(Истина);
		Исключение
			ЗаписьЖурналаРегистрации("ЗаписатьВыбранныйОтвет_НаСервере()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.АнкетыРасширенные, , ОписаниеОшибки());
			Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
		КонецПопытки
	КонецЕсли;	
	
	Возврат Истина;
	
КонецФункции

&НаСервереБезКонтекста
Функция ТаблицаВведенныхОтветовОтветСтрокойАвтоПодбор_НаСервере(Текст)
	
	ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ = Ложь;
	
	Запрос = Новый Запрос();
	Запрос.Текст = "ВЫБРАТЬ ПЕРВЫЕ 10
	               |	ИдентификаторыСтрок.Наименование
	               |ИЗ
	               |	Справочник.ИдентификаторыСтрок КАК ИдентификаторыСтрок
	               |ГДЕ
	               |	ИдентификаторыСтрок.ПометкаУдаления = ЛОЖЬ
	               |	И ИдентификаторыСтрок.Наименование ПОДОБНО &Наименование";
	Запрос.УстановитьПараметр("Наименование", "%"+Текст+"%");
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	Если РезультатЗапроса.Пустой() Тогда
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ
	КонецЕсли;
	
	МассивОтветов = РезультатЗапроса.Выгрузить().ВыгрузитьКолонку(0);
	СписокОтветов = Новый СписокЗначений();
	СписокОтветов.ЗагрузитьЗначения(МассивОтветов);
	
	Возврат СписокОтветов;
КонецФункции














