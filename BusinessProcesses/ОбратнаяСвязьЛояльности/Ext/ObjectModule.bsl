
//**************************************************************************
//Общая (технологическая) часть
//**************************************************************************

Функция ПолучитьКартуМаршрутаОбъектаБП() Экспорт
	ГрафичСхемаКартаМаршрутаОбъектаБП = ЭтотОбъект.ПолучитьКартуМаршрута();
	Возврат ГрафичСхемаКартаМаршрутаОбъектаБП
КонецФункции

Функция ПроверьУсловие(ТочкаМаршрутаБизнесПроцесса)
	
	ВхТочки = ТочкаМаршрутаБизнесПроцесса.ПолучитьВходящиеТочки();
	Если ВхТочки.Количество()=0 Тогда
		Данные = "БизнесПроцесс = " + Ссылка+" ТочкаМаршрута = "+ТочкаМаршрутаБизнесПроцесса.Имя; 
		Комментарий = "Ошибка получения предыдущей точки бизнес-процесса";
		ОбслуживаниеСервер.ЗарегистрироватьСобытие("Ошибка получения предыдущей точки бизнес-процесса", УровеньЖурналаРегистрации.Ошибка, Метаданные.БизнесПроцессы.ОбратнаяСвязьЛояльности, Данные, Комментарий, "Сервер"); 
	КонецЕсли;
	
	ВхТочка = ВхТочки[0];
	Запрос = Новый Запрос;
	Запрос.Текст =
	"ВЫБРАТЬ ПЕРВЫЕ 1
	|	ЗадачаОбратнаяСвязь.ОценкаВыполненияПредшествующейЗадачи КАК Оценка
	|ИЗ
	|	Задача.ЗадачаОбратнаяСвязь КАК ЗадачаОбратнаяСвязь
	|ГДЕ
	|   ЗадачаОбратнаяСвязь.БизнесПроцесс = &БизнесПроцесс
	|	И ЗадачаОбратнаяСвязь.ТочкаМаршрута = &ТочкаМаршрута";
	
	Запрос.УстановитьПараметр("БизнесПроцесс", Ссылка);
	Запрос.УстановитьПараметр("ТочкаМаршрута", ВхТочка);
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	
	Если РезультатЗапроса.Пустой() Тогда
		Результат = Истина;	
		Возврат Результат;
	КонецЕсли;
	
	Выборка = РезультатЗапроса.Выбрать();
	Выборка.Следующий();
	Оценка = Выборка.Оценка;
	
	Если Оценка >= 3 Тогда
		Результат = Истина;
	Иначе
		Результат = Ложь;
	КонецЕсли;
	
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000004"); //Оценка выполнения последней задачи
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, Строка(Выборка.Оценка), "Строка");

	Возврат Результат
	
КонецФункции

Функция ВыполнитьКод(ИмяПараметра)
	Парам = Новый Структура();
	Парам.Вставить(ИмяПараметра);
	
	//Получи значение параметра из учетной политики
	//--------------------------------------------------------------------------	
	ЗначениеПараметраНайдено = РегистрыСведений.УчетнаяПолитика.Получи(Парам);
	Если  ЗначениеПараметраНайдено = Ложь Тогда 
		Возврат "";
	КонецЕсли;
	
	//Проверь наличие значения параметра
	//---------------------------------------------------
	Если ТипЗнч(Парам[ИмяПараметра])<> Тип("Строка") Тогда
		Возврат "";
	КонецЕсли;
	
	Если СтрДлина(Парам[ИмяПараметра]) = 0 Тогда
		Возврат "";
	КонецЕсли;
	
	//Выполнить код
	//-------------
	Попытка
		Выполнить(Парам[ИмяПараметра]);
	Исключение
		Данные = "ИмяПараметра = "+ИмяПараметра+"; ЗначениеПараметра = " + Парам[ИмяПараметра];
		Комментарий = ОписаниеОшибки();
		ОбслуживаниеСервер.ЗарегистрироватьСобытие("Ошибка Выполнить()", УровеньЖурналаРегистрации.Ошибка, Данные, Комментарий,, "Сервер");
	КонецПопытки;		
КонецФункции


//********************************************************************************
// Программный код точек бизнес-процесса
//********************************************************************************

Процедура УстановитьСтатус_ОжидаетОбработки_1(ТочкаМаршрутаБизнесПроцесса)		
	//ВыполнитьКод("АнкетыОбратнаяСвязь__УстановитьСтатус_ОжидаетОбработки_1");
	
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Ожидает обработки", "Строка");
	
КонецПроцедуры

Процедура УстановитьСтатус_ОжидаетСогласования_1(ТочкаМаршрутаБизнесПроцесса)
	//ВыполнитьКод("АнкетыОбратнаяСвязь__УстановитьСтатус_ОжидаетСогласования_1");
	
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Ожидает согласования", "Строка");

КонецПроцедуры

Процедура УстановитьСтатус_ОбращениеЗакрыто(ТочкаМаршрутаБизнесПроцесса)
	
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Закрыто", "Строка");
	
	Попытка
		ЭтотОбъект.ДатаЗавершения=ТекущаяДата();
		ЭтотОбъект.Записать();
	Исключение
		Данные = ЭтотОбъект.Ссылка; 
		Комментарий = ОписаниеОшибки();
		ЗаписьЖурналаРегистрации("УстановитьСтатус_ОбращениеЗакрыто->БП.Записать()", УровеньЖурналаРегистрации.Ошибка, Метаданные.БизнесПроцессы.ОбратнаяСвязьЛояльности, Данные, Комментарий);
	КонецПопытки;
	
КонецПроцедуры

Процедура Условие1ПроверкаУсловия(ТочкаМаршрутаБизнесПроцесса, Результат)	
	Результат = Не ПроверьУсловие(ТочкаМаршрутаБизнесПроцесса);
КонецПроцедуры

Процедура УстановитьСтатус_ВозвращеноВРаботу_2(ТочкаМаршрутаБизнесПроцесса)
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Возвращено в работу", "Строка");
КонецПроцедуры

Процедура УстановитьСтатус_ОжидаетСогласования_2(ТочкаМаршрутаБизнесПроцесса)
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Ожидает согласования", "Строка");
КонецПроцедуры

Процедура Условие2ПроверкаУсловия(ТочкаМаршрутаБизнесПроцесса, Результат)
	Результат = Не ПроверьУсловие(ТочкаМаршрутаБизнесПроцесса);
КонецПроцедуры

//************************************************************************************
// Обработчики событий точек маршрута
//************************************************************************************

Процедура ОбработатьНегативнуюАнкету_1ПриСозданииЗадач(ТочкаМаршрутаБизнесПроцесса, ФормируемыеЗадачи, Отказ)
	Для Каждого ЗадОб Из ФормируемыеЗадачи Цикл
		
		//ЗадОб.Роль = ПредопределенноеЗначение("Справочник.Роли.КлиентскаяСлужбаРегионы_Оператор"); //это задано в точке маршрута
		ЗадОб.Подразделение 		= ЭтотОбъект.ПодразделениеИсполнитель;
		ЗадОб.ДопРеквизитАдресации	= ЭтотОбъект.ДопРеквизитАдресации;

		//Определи исполнителя задачи  по модели ролевой адресации
		//-----------------------------------------------------------
		ЗадОб.Исполнитель	= ПроцессыСервер.НазначьИсполнителя(ЗадОб.Роль, ЗадОб.Подразделение, ЗадОб.ДопРеквизитАдресации);
	КонецЦикла;
КонецПроцедуры

Процедура ПроверитьОбработаннуюНегативнуюАнкету_1ПриСозданииЗадач(ТочкаМаршрутаБизнесПроцесса, ФормируемыеЗадачи, Отказ)
	Для Каждого ЗадОб Из ФормируемыеЗадачи Цикл
		
		//ЗадОб.Роль = ПредопределенноеЗначение("Справочник.Роли.КлиентскаяСлужбаЦентр_Администратор"); //это задано в точке маршрута
		ЗадОб.Подразделение = ЭтотОбъект.ПодразделениеКонтролер;
		
		//Определи исполнителя задачи  по модели ролевой адресации
		//-----------------------------------------------------------
		ЗадОб.Исполнитель	= ПроцессыСервер.НазначьИсполнителя(ЗадОб.Роль, ЗадОб.Подразделение);
		
	КонецЦикла;
КонецПроцедуры

Процедура ОбработатьНегативнуюАнкету_2ПриСозданииЗадач(ТочкаМаршрутаБизнесПроцесса, ФормируемыеЗадачи, Отказ)
	Для Каждого ЗадОб Из ФормируемыеЗадачи Цикл
		
		//ЗадОб.Роль = ПредопределенноеЗначение("Справочник.Роли.КлиентскаяСлужбаРегионы_Оператор"); //это задано в точке маршрута
		ЗадОб.Подразделение 				= ЭтотОбъект.ПодразделениеИсполнитель;
		ЗадОб.ДопРеквизитАдресации	= ЭтотОбъект.ДопРеквизитАдресации;

		//Определи исполнителя задачи  по модели ролевой адресации
		//-----------------------------------------------------------
		ЗадОб.Исполнитель	= ПроцессыСервер.НазначьИсполнителя(ЗадОб.Роль, ЗадОб.Подразделение, ЗадОб.ДопРеквизитАдресации);

	КонецЦикла;
КонецПроцедуры

Процедура ПроверитьОбработаннуюНегативнуюАнкету_2ПриСозданииЗадач(ТочкаМаршрутаБизнесПроцесса, ФормируемыеЗадачи, Отказ)
	Для Каждого ЗадОб Из ФормируемыеЗадачи Цикл
		
		//ЗадОб.Роль = ПредопределенноеЗначение("Справочник.Роли.КлиентскаяСлужбаЦентр_Администратор"); //это задано в точке маршрута
		ЗадОб.Подразделение = ЭтотОбъект.ПодразделениеКонтролер;
		
		//Определи исполнителя задачи  по модели ролевой адресации
		//-----------------------------------------------------------
		ЗадОб.Исполнитель	= ПроцессыСервер.НазначьИсполнителя(ЗадОб.Роль, ЗадОб.Подразделение);

	КонецЦикла;
КонецПроцедуры

Процедура ОбработатьНегативнуюАнкету_3ПриСозданииЗадач(ТочкаМаршрутаБизнесПроцесса, ФормируемыеЗадачи, Отказ)
	Для Каждого ЗадОб Из ФормируемыеЗадачи Цикл
		
		//ЗадОб.Роль = ПредопределенноеЗначение("Справочник.Роли.КлиентскаяСлужбаРегионы_Оператор"); //это задано в точке маршрута
		ЗадОб.Подразделение 				= ЭтотОбъект.ПодразделениеИсполнитель;
		ЗадОб.ДопРеквизитАдресации	= ЭтотОбъект.ДопРеквизитАдресации;

		//Определи исполнителя задачи  по модели ролевой адресации
		//-----------------------------------------------------------
		ЗадОб.Исполнитель	= ПроцессыСервер.НазначьИсполнителя(ЗадОб.Роль, ЗадОб.Подразделение, ЗадОб.ДопРеквизитАдресации);

	КонецЦикла;
КонецПроцедуры

Процедура ПроверитьОбработаннуюНегативнуюАнкету_3ПриСозданииЗадач(ТочкаМаршрутаБизнесПроцесса, ФормируемыеЗадачи, Отказ)
	Для Каждого ЗадОб Из ФормируемыеЗадачи Цикл
		
		//ЗадОб.Роль = ПредопределенноеЗначение("Справочник.Роли.КлиентскаяСлужбаЦентр_Администратор"); //это задано в точке маршрута
		ЗадОб.Подразделение = ЭтотОбъект.ПодразделениеКонтролер;
		
		//Определи исполнителя задачи  по модели ролевой адресации
		//-----------------------------------------------------------
		ЗадОб.Исполнитель	= ПроцессыСервер.НазначьИсполнителя(ЗадОб.Роль, ЗадОб.Подразделение);

	КонецЦикла;
КонецПроцедуры

Процедура ОбработатьНегативнуюАнкету_4ПриСозданииЗадач(ТочкаМаршрутаБизнесПроцесса, ФормируемыеЗадачи, Отказ)
	Для Каждого ЗадОб Из ФормируемыеЗадачи Цикл
		
		//ЗадОб.Роль = ПредопределенноеЗначение("Справочник.Роли.КлиентскаяСлужбаРегионы_Оператор"); //это задано в точке маршрута
		ЗадОб.Подразделение 				= ЭтотОбъект.ПодразделениеИсполнитель;
		ЗадОб.ДопРеквизитАдресации	= ЭтотОбъект.ДопРеквизитАдресации;

		//Определи исполнителя задачи  по модели ролевой адресации
		//-----------------------------------------------------------
		ЗадОб.Исполнитель	= ПроцессыСервер.НазначьИсполнителя(ЗадОб.Роль, ЗадОб.Подразделение, ЗадОб.ДопРеквизитАдресации);

	КонецЦикла;
КонецПроцедуры

Процедура ПроверитьОбработаннуюНегативнуюАнкету_4ПриСозданииЗадач(ТочкаМаршрутаБизнесПроцесса, ФормируемыеЗадачи, Отказ)
	Для Каждого ЗадОб Из ФормируемыеЗадачи Цикл
		
		//ЗадОб.Роль = ПредопределенноеЗначение("Справочник.Роли.КлиентскаяСлужбаЦентр_Администратор"); //это задано в точке маршрута
		ЗадОб.Подразделение = ЭтотОбъект.ПодразделениеКонтролер;
		
		//Определи исполнителя задачи  по модели ролевой адресации
		//-----------------------------------------------------------
		ЗадОб.Исполнитель	= ПроцессыСервер.НазначьИсполнителя(ЗадОб.Роль, ЗадОб.Подразделение);
		
	КонецЦикла;
КонецПроцедуры

Процедура ОбработатьНегативнуюАнкету_5ПриСозданииЗадач(ТочкаМаршрутаБизнесПроцесса, ФормируемыеЗадачи, Отказ)
	Для Каждого ЗадОб Из ФормируемыеЗадачи Цикл
		
		//ЗадОб.Роль = ПредопределенноеЗначение("Справочник.Роли.КлиентскаяСлужбаРегионы_Оператор"); //это задано в точке маршрута
		ЗадОб.Подразделение 				= ЭтотОбъект.ПодразделениеИсполнитель;
		ЗадОб.ДопРеквизитАдресации	= ЭтотОбъект.ДопРеквизитАдресации;

		//Определи исполнителя задачи  по модели ролевой адресации
		//-----------------------------------------------------------
		ЗадОб.Исполнитель	= ПроцессыСервер.НазначьИсполнителя(ЗадОб.Роль, ЗадОб.Подразделение, ЗадОб.ДопРеквизитАдресации);

	КонецЦикла;
КонецПроцедуры

Процедура ПроверитьОбработаннуюНегативнуюАнкету_5ПриСозданииЗадач(ТочкаМаршрутаБизнесПроцесса, ФормируемыеЗадачи, Отказ)
	Для Каждого ЗадОб Из ФормируемыеЗадачи Цикл
		
		//ЗадОб.Роль = ПредопределенноеЗначение("Справочник.Роли.КлиентскаяСлужбаЦентр_Администратор"); //это задано в точке маршрута
		ЗадОб.Подразделение = ЭтотОбъект.ПодразделениеКонтролер;
		
		//Определи исполнителя задачи  по модели ролевой адресации
		//-----------------------------------------------------------
		ЗадОб.Исполнитель	= ПроцессыСервер.НазначьИсполнителя(ЗадОб.Роль, ЗадОб.Подразделение);

	КонецЦикла;
КонецПроцедуры

Процедура Условие3ПроверкаУсловия(ТочкаМаршрутаБизнесПроцесса, Результат)
	Результат = Не ПроверьУсловие(ТочкаМаршрутаБизнесПроцесса);
КонецПроцедуры

Процедура Условие4ПроверкаУсловия(ТочкаМаршрутаБизнесПроцесса, Результат)
	Результат = Не ПроверьУсловие(ТочкаМаршрутаБизнесПроцесса);
КонецПроцедуры

Процедура УстановитьСтатус_ВозвращеноВРаботу_3(ТочкаМаршрутаБизнесПроцесса)
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Возвращено в работу", "Строка");
КонецПроцедуры

Процедура УстановитьСтатус_ОжидаетСогласования_3(ТочкаМаршрутаБизнесПроцесса)
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Ожидает согласования", "Строка");
КонецПроцедуры

Процедура УстановитьСтатус_ВозвращеноВРаботу_4(ТочкаМаршрутаБизнесПроцесса)
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Возвращено в работу", "Строка");
КонецПроцедуры

Процедура УстановитьСтатус_ОжидаетСогласования_4(ТочкаМаршрутаБизнесПроцесса)
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Ожидает согласования", "Строка");
КонецПроцедуры

Процедура УстановитьСтатус_ВозвращеноВРаботу_5(ТочкаМаршрутаБизнесПроцесса)
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Возвращено в работу", "Строка");
КонецПроцедуры

Процедура УстановитьСтатус_ОжидаетСогласования_5(ТочкаМаршрутаБизнесПроцесса)
	Свойство = Справочники.БизнесПроцессыСвойства.НайтиПоКоду("000000001"); //Статус бизнес-процесса
	РегистрыСведений.БизнесПроцессыЗначенияСвойств.Добавить(ТекущаяДата(), ЭтотОбъект.Ссылка, Свойство, "Ожидает согласования", "Строка");
КонецПроцедуры






