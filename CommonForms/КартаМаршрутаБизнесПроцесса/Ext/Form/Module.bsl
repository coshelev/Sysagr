
&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	ЭтаФорма.БизнесПроцесс = ЭтаФорма.Параметры.БизнесПроцесс;
КонецПроцедуры

&НаКлиенте
Процедура ПриОткрытии(Отказ)
	ПоказатьКартуМаршрута(ЭтаФорма.БизнесПроцесс);
КонецПроцедуры

&НаКлиенте
Процедура ПоказатьКартуМаршрута(Команда)
	ЭтаФорма.ГрафичСхема = ПоказатьКартуМаршрута_НаСервере(ЭтаФорма.БизнесПроцесс);
КонецПроцедуры

&НаСервере
Функция ПоказатьКартуМаршрута_НаСервере(БизнесПроцессСсылка)
	
	Если Не ЗначениеЗаполнено(БизнесПроцессСсылка) Тогда
		Возврат Неопределено
	КонецЕсли;
	
	Об = БизнесПроцессСсылка.ПолучитьОбъект();
	ГрафичСхемаКартаМаршрута = Об.ПолучитьКартуМаршрута();

	Возврат ГрафичСхемаКартаМаршрута;
	
КонецФункции

&НаКлиенте
Процедура ГрафичСхемаВыбор(Элемент)
	
	ТекЭлементГрафичСхемы = Элемент.ТекущийЭлемент;
	ИмяТекЭлементаГрафичСхемы = ТекЭлементГрафичСхемы.Имя;
	
	ТочкаМаршрутаБПСсылка = ТекЭлементГрафичСхемы.Значение;	
	
	//Найти задачу бизнес процесса по имени точки маршрута
	//----------------------------------------------------
	Задача = НайдиЗадачуБизнесПроцессаПоТочкеМаршрута(ЭтаФорма.БизнесПроцесс, ТочкаМаршрутаБПСсылка );	
	Если Не ЗначениеЗаполнено(Задача) Тогда
		Возврат
	КонецЕсли;
	
	//Если оказались здесь, значит Задача содержит ссылку
	//----------------------------------------------------
	Если ТипЗнч(Задача) = Тип("ЗадачаСсылка.ЗадачаОбратнаяСвязь") Тогда	
		Парам = Новый Структура();
		Парам.Вставить("Ключ", Задача);
		Парам.Вставить("ТолькоПросмотр", Истина);
		Фрм 		= ПолучитьФорму("Задача.ЗадачаОбратнаяСвязь.Форма.ФормаЗадачи", Парам);
		Фрм.Открыть();
	КонецЕсли;
КонецПроцедуры

&НаСервереБезКонтекста
Функция НайдиЗадачуБизнесПроцессаПоТочкеМаршрута(БизнесПроцессСсылка, ТочкаМаршрутаСсылка)
	
	ЗначениеПоУмолчанию = "";
	
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ ПЕРВЫЕ 1
	|	ЗадачаОбратнаяСвязь.Ссылка КАК Ссылка
	|ИЗ
	|	Задача.ЗадачаОбратнаяСвязь КАК ЗадачаОбратнаяСвязь
	|ГДЕ
	|	ЗадачаОбратнаяСвязь.БизнесПроцесс = &БизнесПроцесс
	|	И ЗадачаОбратнаяСвязь.ТочкаМаршрута = &ТочкаМаршрута";
	
	Запрос.УстановитьПараметр("БизнесПроцесс", БизнесПроцессСсылка);
	Запрос.УстановитьПараметр("ТочкаМаршрута", ТочкаМаршрутаСсылка);
	
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	
	Если РезультатЗапроса.Пустой() Тогда
		Возврат ЗначениеПоУмолчанию;	
	КонецЕсли;
	
	Выборка = РезультатЗапроса.Выбрать();
	Выборка.Следующий();
	ЗадачаСсылка = Выборка.Ссылка;
	
	Возврат ЗадачаСсылка;
	
	
КонецФункции

&НаКлиенте
Процедура СтрВкладкиПриСменеСтраницы(Элемент, ТекущаяСтраница)
	Если ТекущаяСтраница.Имя = "СтрГант" Тогда
		СформируйГанта(ЭтаФорма.БизнесПроцесс); 
	КонецЕсли;
КонецПроцедуры

&НаСервере
Процедура СформируйГанта(БизнесПроцессСсылка) 
	ТекДата 		= ТекущаяДата();
	НачалоПериода 	= НачалоМесяца(ТекДата);
	КонецПериода	= КонецМесяца(ТекДата);
	

	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	ЗадачаОбратнаяСвязь.Ссылка КАК Ссылка,
	|	ЗадачаОбратнаяСвязь.Дата КАК ДатаПостановки,
	|	ЗадачаОбратнаяСвязь.ДатаВыполнения КАК ДатаВыполнения,
	|	ЗадачаОбратнаяСвязь.Выполнена КАК Выполнена,
	|	ЗадачаОбратнаяСвязь.Исполнитель КАК Исполнитель
	|ИЗ
	|	Задача.ЗадачаОбратнаяСвязь КАК ЗадачаОбратнаяСвязь
	|ГДЕ
	|	ЗадачаОбратнаяСвязь.БизнесПроцесс = &БизнесПроцесс";
	
	Запрос.УстановитьПараметр("БизнесПроцесс", БизнесПроцессСсылка);
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	Если РезультатЗапроса.Пустой() Тогда
		Возврат;
	КонецЕсли;
	
	
	ЭтаФорма.Гант.Очистить();
	
	//ЭтаФорма.Гант.ОтображениеИнтервала=ОтображениеИнтервалаДиаграммыГанта.Плоский;
	ЭтаФорма.Гант.ЕдиницаПериодическогоВарианта	=	ТипЕдиницыШкалыВремени.День;
	ЭтаФорма.Гант.ПоддержкаМасштаба				=	ПоддержкаМасштабаДиаграммыГанта.Период;
	//ЭтаФорма.Гант.ОтображатьЛегенду				=	Ложь;
	
	Выборка = РезультатЗапроса.Выбрать();
	Пока Выборка.Следующий()Цикл
	
		Точка1 = ЭтаФорма.Гант.Точки.Добавить();
		Точка1.Текст = Выборка.Исполнитель;
		Точка1.Значение = Выборка.Исполнитель;
		
		Серия1 = ЭтаФорма.Гант.Серии.Добавить();
		ЗначениеДиагрГанта = ЭтаФорма.Гант.ПолучитьЗначение(Точка1, Серия1);

	    Интервал1 = ЗначениеДиагрГанта.Добавить();
		Интервал1.Начало 	= Выборка.ДатаПостановки;
		
		Если Выборка.Выполнена = Истина Тогда
			Интервал1.Конец 	= макс(Выборка.ДатаПостановки, Выборка.ДатаВыполнения);
			Интервал1.Цвет=webцвета.Красный;
		Иначе
			Интервал1.Конец 	= ТекущаяДата();;
			Интервал1.Цвет=webцвета.Зеленый;
		КонецЕсли;

		
	//	Если Не ЗначениеЗаполнено(Аг.НачБлокировки) И Не ЗначениеЗаполнено(Аг.КонБлокировки)  Тогда
	//		//ЗначениеДиагрГанта = ЭтаФорма.Гант.ПолучитьЗначение(Точка1, Серия1);
	//		////ЗначениеДиагрГанта.Редактирование = Истина;
	//		//Интервал1 = ЗначениеДиагрГанта.Добавить();
	//		//Интервал1.Начало 	= НачалоПериода;	
	//		//Интервал1.Конец 	= КонецПериода;	
	//	КонецЕсли;
	//		
	//	Если ЗначениеЗаполнено(Аг.НачБлокировки) И ЗначениеЗаполнено(Аг.КонБлокировки)  Тогда
	//		Если Аг.НачБлокировки < НачалоПериода Тогда
	//			ЗначениеДиагрГанта = ЭтаФорма.Гант.ПолучитьЗначение(Точка1, Серия2);
	//			ЗначениеДиагрГанта.Редактирование = Истина;
	//			Интервал2 = ЗначениеДиагрГанта.Добавить();
	// 			Интервал2.Начало = НачалоПериода;	
	//			Если Аг.КонБлокировки < КонецПериода Тогда
	//				Интервал2.Конец = Аг.КонБлокировки;	

	//				//ЗначениеДиагрГанта = ЭтаФорма.Гант.ПолучитьЗначение(Точка1, Серия1);
	//				////ЗначениеДиагрГанта.Редактирование = Истина;
	//				//Интервал1 = ЗначениеДиагрГанта.Добавить();
	//				//Интервал1.Начало = Аг.КонБлокировки;	
	//				//Интервал1.Конец = КонецПериода;		
	//			КонецЕсли;
	//			Если Аг.КонБлокировки >= КонецПериода Тогда
	//				 Интервал2.Конец = КонецПериода;	
	//			КонецЕсли;		 
	//		КонецЕсли;
	//		
	//		Если Аг.НачБлокировки > НачалоПериода Тогда
	//			//ЗначениеДиагрГанта = ЭтаФорма.Гант.ПолучитьЗначение(Точка1, Серия1);
	//			////ЗначениеДиагрГанта.Редактирование = Истина;
	//			//Интервал1 = ЗначениеДиагрГанта.Добавить();
	//			//Интервал1.Начало = НачалоПериода;	
	//			//Интервал1.Конец = Аг.НачБлокировки;
	//			
	//			ЗначениеДиагрГанта = ЭтаФорма.Гант.ПолучитьЗначение(Точка1, Серия2);
	//			ЗначениеДиагрГанта.Редактирование = Истина;
	//			Интервал2 = ЗначениеДиагрГанта.Добавить();
	// 			Интервал2.Начало = Аг.НачБлокировки;	
	//			Если Аг.КонБлокировки >= КонецПериода Тогда
	//				Интервал2.Конец = КонецПериода;		
	//			КонецЕсли;
	//			Если Аг.КонБлокировки < КонецПериода Тогда
	//				Интервал2.Конец= Аг.КонБлокировки;
	//				
	//				//ЗначениеДиагрГанта = ЭтаФорма.Гант.ПолучитьЗначение(Точка1, Серия1);
	//				////ЗначениеДиагрГанта.Редактирование = Истина;
	//				//Интервал1 = ЗначениеДиагрГанта.Добавить();
	//				//Интервал1.Начало = Интервал2.Конец;	
	//				//Интервал1.Конец = КонецПериода;
	//			КонецЕсли;
	//		КонецЕсли;
	//		
	//		
	//	КонецЕсли;

	//
	КонецЦикла;
	
КонецПроцедуры



