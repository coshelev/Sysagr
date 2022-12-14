
&НаКлиенте
Процедура ПолучиИдентификатор(Команда)
	Если Не ЗначениеЗаполнено(ЭтаФорма.РеквизитСсылкаНаСправочник) Тогда
		Сообщить("Не заполнен реквизит: "+ЭтаФорма.РеквизитСсылкаНаСправочник);
		Возврат
	Иначе
		ПолучиИдентификатор_НаСервере(ЭтаФорма.РеквизитСсылкаНаСправочник);
	КонецЕсли;
КонецПроцедуры

&НаСервереБезКонтекста
Процедура ПолучиИдентификатор_НаСервере(РеквизитСсылкаНаСправочник)
	Сообщить(РеквизитСсылкаНаСправочник.УникальныйИдентификатор());
	Сообщить(РеквизитСсылкаНаСправочник.Метаданные().Имя);
КонецПроцедуры

&НаКлиенте
Процедура ПокажиВыборИзСписка(Элемент)
	СписокТиповЗначений = ПолучиСписокТиповЗначений();
	
	ДопПарамОбработчикаОповещения = Элемент;
	Оп = Новый ОписаниеОповещения("ОбработкаОповещения1", ЭтотОбъект, ДопПарамОбработчикаОповещения);
	
	ПоказатьВыборИзСписка(Оп, СписокТиповЗначений, Элемент);
КонецПроцедуры

&НаКлиенте
Процедура ОбработкаОповещения1(ВыбЗнач, ДопПараметры) Экспорт
	
	Если ВыбЗнач = Неопределено Тогда
		Возврат;
	КонецЕсли;
	
	ЭтаФорма.Запись.ТипЗначения = ВыбЗнач;
	
	ЭтаФорма.Запись.Значение="";
	ЭтаФорма.Представление="";
	
	Если СтрНайти(ЭтаФорма.Запись.ТипЗначения, "Ссылка")>0 Тогда
		ИдФормы = СтрЗаменить(ЭтаФорма.Запись.ТипЗначения, "Ссылка", "");
		ИдФормы = ИдФормы+".ФормаВыбора";
		ОткрытьФорму(ИдФормы,,ДопПараметры);
	КонецЕсли;
	
КонецПроцедуры


&НаСервере
Функция ПолучиСписокТиповЗначений()
	
	СписокТиповЗначений = Новый СписокЗначений();
	
	СписокТиповЗначений.Добавить("Булево", "Булево");
	СписокТиповЗначений.Добавить("Строка", "Строка");
	СписокТиповЗначений.Добавить("Число", "Число");

	МассивТипов = Справочники.ТипВсеСсылки().Типы();	
	Для Каждого Эл Из МассивТипов Цикл
		ИмяТипаСтрокой = "СправочникСсылка."+Метаданные.НайтиПоТипу(Эл).Имя;
		СписокТиповЗначений.Добавить(ИмяТипаСтрокой)
	КонецЦикла;
	
	МассивТипов = Документы.ТипВсеСсылки().Типы();
	Для Каждого Эл Из МассивТипов Цикл
		ИмяТипаСтрокой = "ДокументСсылка."+Метаданные.НайтиПоТипу(Эл).Имя;
		СписокТиповЗначений.Добавить(ИмяТипаСтрокой);
	КонецЦикла;

	МассивТипов = Перечисления.ТипВсеСсылки().Типы();
	Для Каждого Эл Из МассивТипов Цикл
		ИмяТипаСтрокой = "ПеречислениеСсылка."+Метаданные.НайтиПоТипу(Эл).Имя;
		СписокТиповЗначений.Добавить(ИмяТипаСтрокой);
	КонецЦикла;	
	
	Возврат СписокТиповЗначений
КонецФункции


&НаКлиенте
Процедура ЗначениеНачалоВыбора(Элемент, ДанныеВыбора, СтандартнаяОбработка)
	
	ПокажиВыборИзСписка(Элемент)
	
КонецПроцедуры

&НаКлиенте
Процедура ЗначениеОбработкаВыбора(Элемент, ВыбранноеЗначение, СтандартнаяОбработка)
	
	Если Не ЗначениеЗаполнено(ВыбранноеЗначение) Тогда
		Возврат
	КонецЕсли;
	
	ТипЗначенияСтрокой = ЭтаФорма.Запись.ТипЗначения;  // Например СправочникСсылка.Холдеры

	Если Не ЗначениеЗаполнено(ТипЗначенияСтрокой) Тогда
		Возврат
	КонецЕсли;
	
	Если СтрНайти(ТипЗначенияСтрокой, "Ссылка")= 0 Тогда
		Возврат
	КонецЕсли;

	СтандартнаяОбработка = Ложь;
	ЭтаФорма.Представление = ВыбранноеЗначение;
	ЭтаФорма.Запись.Значение = ВыбранноеЗначение.УникальныйИдентификатор();

КонецПроцедуры

&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	СформироватьПредставлениеСсылок();
КонецПроцедуры

&НаСервере
Процедура СформироватьПредставлениеСсылок()
	
	ТипЗначенияСтрокой = ЭтаФорма.Запись.ТипЗначения;  // Например СправочникСсылка.Холдеры
	
	Если Не ЗначениеЗаполнено(ТипЗначенияСтрокой) Тогда
		Возврат
	КонецЕсли;
	
	Если СтрНайти(ТипЗначенияСтрокой, "Ссылка")= 0 Тогда
		Возврат
	КонецЕсли;

	ЭтаФорма.Представление = xmlзначение(Тип(ТипЗначенияСтрокой), ЭтаФорма.Запись.Значение);
КонецПроцедуры

&НаКлиенте
Процедура ЗначениеПриИзменении(Элемент)
	
	Если СтрНайти(ЭтаФорма.Запись.ТипЗначения, "Ссылка")> 0 Тогда
		ЭтаФорма.Запись.ТипЗначения = "Строка";
		Возврат
	КонецЕсли;
	
КонецПроцедуры

&НаКлиенте
Процедура ПередЗаписью(Отказ, ПараметрыЗаписи)
	ЕстьОшибки = Ложь;
	
	Если ЭтаФорма.Запись.ТипЗначения = "Число" Тогда
		й=1;
		Попытка
			й=й+ЭтаФорма.Запись.Значение;
		Исключение
			Сооб = Новый СообщениеПользователю();
			Сооб.Поле="ЭтаФорма.Значение";
			Сооб.Текст = ОписаниеОшибки();
			Сооб.Сообщить();
			ЕстьОшибки = Истина;
		КонецПопытки
	КонецЕсли;
	
	Если ЭтаФорма.Запись.ТипЗначения = "Булево" Тогда
		Если ЭтаФорма.Запись.Значение = "Истина" Или ЭтаФорма.Запись.Значение = "Ложь" Тогда
		Иначе
			Сооб = Новый СообщениеПользователю();
			Сооб.Поле="ЭтаФорма.Значение";
			Сооб.Текст = "Длят типа Булево допускаются только значения Истина и Ложь";
			Сооб.Сообщить();
			ЕстьОшибки = Истина;	
		КонецЕсли;
	КонецЕсли;

	
	Если ЕстьОшибки Тогда
		Отказ = Истина;
	КонецЕсли;
	
КонецПроцедуры
