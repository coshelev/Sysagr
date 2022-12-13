﻿Функция ЗагрузитьИзОУ(ИсточникДанных, ГУИД, Код, Наименование, ПолноеНаименование,ТелВнутрНомер="", АдресЭлПочты="", РуководительГУИД="", ЦелеваяТочкаГУИД = "") Экспорт
	//Параметры:
	//ИсточникДанных (строка) 	- условное обозначение базы-источника(путь к базе-источнику в формате поключения по com-соединению);
	//ГУИД 						- ссылка в базе источнике
	//Код 						- код в базе источнике
	//Наименование 				- название в базе источнике
	//ТелВнутрНомер				- номер внутреннего телефона абонента
	//РуководительГУИД			- ГУИД руководителя
	//--------------------------------------------------------------------
	//Загружает или обновляет данные сотрудника из баз-источников
	
	Данные = "ИсточникДанных = "+ИсточникДанных+"; ГУИД = "+ГУИД+"; Код = "+Код+"; Наименование = "+Наименование+"ПолноеНаименование = "+ПолноеНаименование+
	"; ТелВнутрНомер = "+ ТелВнутрНомер+"; АдресЭлПочты = "+АдресЭлПочты+"; РуководительГУИД = "+РуководительГУИД+"; ЦелеваяТочкаГУИД ="+ЦелеваяТочкаГУИД;
	
	Сообщить(Данные);
	ЗначениеПоУмолчанию = Ложь;
	
	ТипСтрока = Тип("Строка");
	Доступно = ТипЗнч(ИсточникДанных) 				= ТипСтрока;
	Доступно = Доступно И ТипЗнч(ГУИД) 				= ТипСтрока;
	Доступно = Доступно И ТипЗнч(Код) 				= ТипСтрока;
	Доступно = Доступно И ТипЗнч(Наименование) 		= ТипСтрока;
	Доступно = Доступно И ТипЗнч(ПолноеНаименование)= ТипСтрока;
	Доступно = Доступно И ТипЗнч(ТелВнутрНомер)		= ТипСтрока; 
	Доступно = Доступно И ТипЗнч(АдресЭлПочты)		= ТипСтрока; 
	Доступно = Доступно И ТипЗнч(РуководительГУИД)	= ТипСтрока; 
	Доступно = Доступно И ТипЗнч(ЦелеваяТочкаГУИД)	= ТипСтрока; 
	Доступно = Доступно И ЗначениеЗаполнено(ИсточникДанных);
	Доступно = Доступно И ЗначениеЗаполнено(ГУИД);
	Доступно = Доступно И ЗначениеЗаполнено(Код);
	Доступно = Доступно И ЗначениеЗаполнено(Наименование);
	
	Если Не Доступно Тогда
		Комментарий = "Ошибка в типе или заполнении аргументов";
		ЗаписьЖурналаРегистрации("Загрузить()", УровеньЖурналаРегистрации.Ошибка, Метаданные.Справочники.Сотрудники, Данные, Комментарий);
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	Ссылка = Справочники.Сотрудники.ПустаяСсылка();
	Ссылка = НайдиПоЗначениюКлюча(ГУИД);
	Если Ссылка = Справочники.Сотрудники.ПустаяСсылка() Тогда
		Об = Справочники.Сотрудники.СоздатьЭлемент();
	Иначе
		Об = Ссылка.ПолучитьОбъект();
		Сообщить("Получен объект");
	КонецЕсли;
	
	Об.Наименование 		= Наименование;
	Об.ФИО 					= ПолноеНаименование;
	Об.ЭлектроннаяПочта		= АдресЭлПочты;
	Об.ВнутреннийТелефон	= ТелВнутрНомер;
	
	//Сообщить("РуководительГУИД");
	//Заполни руководителя (у справочника иерархия элементов)
	//------------------------------------------------------------------
	Если ЗначениеЗаполнено(РуководительГУИД) Тогда
		РукСсылка = НайдиПоЗначениюКлюча(РуководительГУИД);
		Если РукСсылка <> Справочники.Сотрудники.ПустаяСсылка() Тогда
			Об.Родитель = РукСсылка;
		КонецЕсли;
	КонецЕсли;
	
	Об.Руководитель = РуководительГУИД;
	Об.ЦелеваяТочка = ЦелеваяТочкаГУИД;
	
	Сообщить("ЭтоНовый");	
	Если Об.ЭтоНовый() Тогда
		НоваяСтрока = Об.КлючиВИсточникахДанных.Добавить();
		НоваяСтрока.Период = ТекущаяДата();
		
		//Установи тип данных
		//-------------------
		//Запрос = Новый Запрос();
		//Запрос.Текст = 
		//"ВЫБРАТЬ
		//|	ИБ_ТипыДанных.Ссылка КАК Ссылка
		//|ИЗ
		//|	Справочник.ИБ_ТипыДанных КАК ИБ_ТипыДанных
		//|ГДЕ
		//|	ИБ_ТипыДанных.Наименование ПОДОБНО &Наименование
		//|	И ИБ_ТипыДанных.ИсточникДанных.Префикс = &Префикс";
		//Запрос.УстановитьПараметр("Наименование", "%Справочник.Сотрудники%");
		//Запрос.УстановитьПараметр("Префикс", ИсточникДанных);
		//РезультатЗапроса = Запрос.Выполнить();
		//Если Не РезультатЗапроса.Пустой() Тогда
		//	ТипДан = РезультатЗапроса.Выгрузить()[0][0];
		//	НоваяСтрока.ТипКлюча = ТипДан;
		//КонецЕсли;
		НоваяСтрока.ТипКлюча = Справочники.ИБ_ТипыДанных.НайтиПоКоду("000000003");
		
		НоваяСтрока.ЗначениеКлюча			= ГУИД;
		НоваяСтрока.ПредставлениеКлюча		= Наименование;
		НоваяСтрока.ДопПредставлениеКлюча	= Код;
	КонецЕсли;
	
	Попытка
		//Сообщить("Попытка");
		Об.Записать();
	Исключение
		Комментарий = ОписаниеОшибки();
		ЗаписьЖурналаРегистрации("Загрузить()", УровеньЖурналаРегистрации.Ошибка, Метаданные.Справочники.Сотрудники, Данные, Комментарий);
		Возврат  ЗначениеПоУмолчанию 
	КонецПопытки;
	
	//Сообщить("Возврат");
	Возврат Истина;

КонецФункции

 Функция НайдиПоЗначениюКлюча(Ключ)
	ЗначениеПоУмолчанию = Справочники.Сотрудники.ПустаяСсылка();
	Запрос = Новый Запрос();
	Запрос.Текст = "ВЫБРАТЬ
	               |	СотрудникиКлючиВИсточникахДанных.Ссылка КАК Ссылка
	               |ИЗ
	               |	Справочник.Сотрудники.КлючиВИсточникахДанных КАК СотрудникиКлючиВИсточникахДанных
	               |ГДЕ
	               |	СотрудникиКлючиВИсточникахДанных.ЗначениеКлюча = &ЗначениеКлюча";
	Запрос.УстановитьПараметр("ЗначениеКлюча", Ключ);
	РезультатЗапроса = Запрос.Выполнить();
	Если РезультатЗапроса.Пустой() Тогда
		Возврат ЗначениеПоУмолчанию;
	Иначе
		Возврат РезультатЗапроса.Выгрузить()[0][0];
	КонецЕсли;
КонецФункции

Функция НайдиПоВнутреннемуТелефону(ВнутрТелефонНомер) Экспорт
	// Параметр: 			  ВнутрТелефонНомер (строка)	- номер телефона, адред эл.почты и прочие
	// Возвращаемое значение: ссылка на контрагента
	
	ЗначениеПоУмолчанию = Справочники.Сотрудники.ПустаяСсылка();
	
	Доступно = ТипЗнч(ВнутрТелефонНомер) = Тип("Строка");
	Доступно = Доступно И СтрДлина(ВнутрТелефонНомер) = 4;
	
	Если Не Доступно Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	Запрос = Новый Запрос();
	//Запрос.Текст =  "ВЫБРАТЬ ПЕРВЫЕ 1
	//                |	ОбъектыПривязка.Владелец КАК Владелец
	//                |ИЗ
	//                |	РегистрСведений.ОбъектыПривязка КАК ОбъектыПривязка
	//                |ГДЕ
	//                |	ОбъектыПривязка.Объект ССЫЛКА Справочник.ТелВнутренние
	//                |	И ВЫРАЗИТЬ(ОбъектыПривязка.Объект КАК Справочник.ТелВнутренние).Код = &ВнутрТелефонНомер";

	Запрос.Текст = "ВЫБРАТЬ
	               |	Сотрудники.Ссылка КАК Ссылка
	               |ИЗ
	               |	Справочник.Сотрудники КАК Сотрудники
	               |ГДЕ
	               |	Сотрудники.ВнутреннийТелефон = &ВнутрТелефонНомер";
				   
	Запрос.УстановитьПараметр("ВнутрТелефонНомер", ВнутрТелефонНомер);
	РезультатЗапроса = Запрос.Выполнить();
	
	Если РезультатЗапроса.Пустой() Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	Рез = РезультатЗапроса.Выгрузить()[0][0];
	Возврат Рез
КонецФункции 

Функция СрезПоследних(Период, ЗначенияКлючей) Экспорт
	
	ТЗ = Новый ТаблицаЗначений();
	ТЗ.Колонки.Добавить("Ссылка", Новый ОписаниеТипов("СправочникСсылка.ТочкиЦелевые"));
	ТЗ.Колонки.Добавить("КлючИсточник", Новый ОписаниеТипов("Строка"));
	
	ЗначениеПоУмолчанию = ТЗ;
	
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	Ключи.Ссылка КАК Ссылка,
	|	Ключи.Период КАК Период,
	|	Ключи.ЗначениеКлюча КАК ЗначениеКлюча
	|ПОМЕСТИТЬ ВТ01_Детальные
	|ИЗ
	|	Справочник.ТочкиЦелевые.КлючиВИсточникахДанных КАК Ключи
	|ГДЕ
	|	Ключи.Период <= &Период
	|	И Ключи.ЗначениеКлюча В(&ЗначенияКлючей)
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ РАЗЛИЧНЫЕ
	|	ВТ01_Детальные.Ссылка КАК Ссылка,
	|	ВТ01_Детальные.ЗначениеКлюча КАК ЗначениеКлюча,
	|	МАКСИМУМ(ВТ01_Детальные.Период) КАК Период
	|ИЗ
	|	ВТ01_Детальные КАК ВТ01_Детальные
	|
	|СГРУППИРОВАТЬ ПО
	|	ВТ01_Детальные.Ссылка,
	|	ВТ01_Детальные.ЗначениеКлюча";
	
	Если Не ЗначениеЗаполнено(ЗначенияКлючей) Тогда
		Запрос.Текст = СтрЗаменить(Запрос.Текст, "Ключи.ЗначениеКлюча В(&ЗначенияКлючей)", "ИСТИНА");
	Иначе
		Запрос.УстановитьПараметр("ЗначенияКлючей", ЗначенияКлючей);
	КонецЕсли;
	
	РезультатЗапроса = Запрос.Выполнить();
	Если РезультатЗапроса.Пустой() Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	Выборка = РезультатЗапроса.Выбрать();
	Пока Выборка.Следующий() Цикл
		НоваяСтрока = ТЗ.Добавить();
		НоваяСтрока.Ссылка = Выборка.Ссылка;
		НоваяСтрока.КлючИсточник = Выборка.ЗначениеКлюча;
	КонецЦикла;
	
	Возврат ТЗ;
	
КонецФункции
